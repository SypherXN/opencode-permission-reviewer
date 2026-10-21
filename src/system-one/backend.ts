import { TypeSafeClient } from "@typesafe-ai/sdk"
import type { ReviewAttempt } from "../core/review-attempt.ts"
import { buildEvidenceResult } from "../context.ts"
import { applyEscalationDisposition } from "../escalation.ts"
import { formatFailureReason } from "../failure-reason.ts"
import { DEFAULT_TENANT_POLICY, REVIEWER_SYSTEM_PROMPT } from "../policy.ts"
import { redactSecrets } from "../redact.ts"
import { splitModel } from "../config.ts"
import type { ReviewEnvelope, ReviewExecutionResult, ReviewerConfig } from "../types.ts"
import {
  OPR_JEV_MODULE,
  interpretCooldownReport,
  interpretModuleSelection,
  isStructuredRateLimit,
  permitFallbackModel,
  permitSelectedModel,
  type ModuleLogger,
  type ModuleRoutingClient,
} from "./module-routing.ts"
import {
  enforceParsedSystemOneReview,
  parseSystemOneReview,
  SYSTEM_ONE_QUESTIONS,
  type SystemOneState,
} from "./review.ts"

export type ReasoningEscalation = (
  envelope: ReviewEnvelope,
  attempt: ReviewAttempt,
) => Promise<ReviewExecutionResult>

export type SystemOneInvoke = (state: SystemOneState, signal: AbortSignal) => Promise<unknown>

const SYSTEM_ONE_RETRY = {
  maxRetries: 2,
  backoffInitialMs: 400,
  backoffMaxMs: 800,
  httpStatuses: new Set([503]),
  respectRetryAfter: false,
  apiConnectionError: false,
  apiTimeoutError: false,
}

function reconcileReasoningEscalation(result: ReviewExecutionResult): ReviewExecutionResult {
  if (result.kind !== "allow" || result.decision?.evidence_completeness === "sufficient") {
    return result
  }
  const reviewerOutcome = result.decision?.outcome ?? result.reviewerOutcome
  return {
    ...result,
    kind: "escalate",
    reason:
      "The reasoning reviewer did not find sufficient evidence to override the System One escalation.",
    ...(reviewerOutcome === undefined ? {} : { reviewerOutcome }),
  }
}

export function createSystemOneInvoker(
  config: ReviewerConfig,
  fetchImpl?: TypeSafeClient["fetch"],
): SystemOneInvoke {
  const { providerID, modelID } = splitModel(config.model)
  const keyName =
    providerID === "opencode"
      ? "OPENCODE_API_KEY"
      : providerID === "commandcode"
        ? "CMD_API_KEY"
        : "TYPESAFE_API_KEY"
  const apiKey = process.env[keyName]?.trim()
  if (!apiKey) throw new Error(`Missing ${keyName} for System One reviewer ${config.model}`)
  const client = new TypeSafeClient({
    apiKey,
    ...(providerID === "opencode"
      ? { baseURL: "https://opencode.ai/zen" }
      : providerID === "commandcode"
        ? { baseURL: "https://api.commandcode.ai/provider" }
        : {}),
    defaultModel: modelID,
    logLevel: "off",
    timeout: config.timeoutMs,
    retry: SYSTEM_ONE_RETRY,
    ...(fetchImpl ? { fetch: fetchImpl } : {}),
  })
  return async (state, signal) => {
    const deadline = AbortSignal.timeout(config.timeoutMs)
    const boundedSignal = AbortSignal.any([signal, deadline])
    const { data } = await client
      .systemOne(
        { model: modelID, state, questions: SYSTEM_ONE_QUESTIONS },
        { signal: boundedSignal, timeout: config.timeoutMs },
      )
      .withResponse()
    return data
  }
}

/** Calls Jev directly and delegates only valid but difficult decisions. */
export class SystemOneReviewerBackend {
  private readonly jobs = new Set<Promise<ReviewExecutionResult>>()
  private readonly createInvoke: (config: ReviewerConfig) => SystemOneInvoke

  constructor(
    private readonly config: ReviewerConfig,
    private readonly escalation?: ReasoningEscalation,
    private readonly escalationModel?: string,
    private readonly invoke?: SystemOneInvoke,
    private readonly recordReviewerMs?: (envelope: ReviewEnvelope, ms: number) => void,
    private readonly modules?: ModuleRoutingClient,
    createInvoke?: (config: ReviewerConfig) => SystemOneInvoke,
    private readonly logger?: ModuleLogger,
  ) {
    this.createInvoke = createInvoke ?? createSystemOneInvoker
  }

  owns(): boolean {
    return false
  }

  review(
    envelope: ReviewEnvelope,
    attempt: ReviewAttempt,
    escalation: ReasoningEscalation | undefined = this.escalation,
  ): Promise<ReviewExecutionResult> {
    const job = this.runReview(envelope, attempt, escalation).finally(() => this.jobs.delete(job))
    this.jobs.add(job)
    return job
  }

  async waitForIdle(): Promise<void> {
    await Promise.allSettled([...this.jobs])
  }

  private ensureActive(attempt: ReviewAttempt): void {
    if (attempt.active()) return
    throw attempt.signal.reason instanceof Error
      ? attempt.signal.reason
      : new Error("Review cancelled")
  }

  private failClosed(reason: string, reviewerModel = this.config.model): ReviewExecutionResult {
    return applyEscalationDisposition(
      {
        kind: "escalate",
        reason,
        decisionSource: "failure-safe",
        reviewerModel,
      },
      this.config,
      "reviewer-failure",
    )
  }

  private async conclude(
    response: unknown,
    config: ReviewerConfig,
    envelope: ReviewEnvelope,
    attempt: ReviewAttempt,
    escalation: ReasoningEscalation | undefined,
  ): Promise<ReviewExecutionResult> {
    const parsed = parseSystemOneReview(response, config)
    if (!parsed) {
      return applyEscalationDisposition(
        {
          kind: "escalate",
          reason: "System One reviewer returned a missing, invalid, or ambiguous decision.",
          decisionSource: "failure-safe",
          reviewerModel: config.model,
        },
        this.config,
        "invalid-decision",
      )
    }

    const enforced = enforceParsedSystemOneReview(parsed, config)
    if (enforced.kind !== "escalate") {
      return {
        ...enforced,
        decisionSource: "system-one-reviewer",
        reviewerModel: config.model,
      }
    }

    if (escalation && this.escalationModel && parsed.reasoningRecommended) {
      const secondary = reconcileReasoningEscalation(await escalation(envelope, attempt))
      return {
        ...secondary,
        reviewerModel: secondary.reviewerModel ?? this.escalationModel,
        reviewerEscalatedFrom: { model: config.model, reason: enforced.reason },
      }
    }

    return applyEscalationDisposition(
      {
        ...enforced,
        decisionSource: "system-one-reviewer",
        reviewerModel: config.model,
      },
      this.config,
      "general",
    )
  }

  private async reviewRouted(
    state: SystemOneState,
    envelope: ReviewEnvelope,
    attempt: ReviewAttempt,
    escalation: ReasoningEscalation | undefined,
    useModel: (model: string) => void,
  ): Promise<ReviewExecutionResult> {
    const routing = this.config.moduleRouting
    if (!routing || !this.modules) {
      return this.failClosed(
        "Quartermaster module routing is enabled, but no Quartermaster client is available, so the direct Jev transport was not called.",
      )
    }
    let blocked: { providerID: string; modelID: string } | undefined
    for (let transport = 0; transport < 2; transport++) {
      this.ensureActive(attempt)
      const selection = interpretModuleSelection(
        await attempt.wait(this.modules.select(attempt.signal)),
      )
      const selected = permitSelectedModel(routing, selection, blocked)
      // Quartermaster could not be reached (it threw or timed out) means no
      // decision came back at all, not a refusal. Fall back to the trusted
      // configured reviewer model, under the same allowlist and paid-use
      // policy, instead of failing the review closed. An explicit Quartermaster
      // decision (no module, no eligible model) and a broken contract still
      // fail closed.
      let chosen = selected
      if (!selected.ok) {
        const fallback = permitFallbackModel(routing, selection, this.config.model, blocked)
        if (fallback.ok) {
          this.logger?.(
            "Quartermaster module selection gave no decision; using the configured reviewer model",
            { reason: selected.reason, model: fallback.model },
          )
          chosen = fallback
        }
      }
      if (!chosen.ok) return this.failClosed(chosen.reason)
      useModel(chosen.model)
      const selectedConfig = { ...this.config, model: chosen.model }
      let response: unknown
      try {
        this.ensureActive(attempt)
        response = await attempt.wait(this.createInvoke(selectedConfig)(state, attempt.signal))
      } catch (error) {
        if (attempt.signal.aborted || !isStructuredRateLimit(error)) throw error
        if (transport === 1) {
          return this.failClosed(
            "The replacement System One model also returned HTTP 429, so the review stopped without another call.",
            chosen.model,
          )
        }
        this.ensureActive(attempt)
        const report = interpretCooldownReport(
          await attempt.wait(
            this.modules.reportRateLimit(
              { providerID: chosen.providerID, modelID: chosen.modelID },
              attempt.signal,
            ),
          ),
          {
            module: OPR_JEV_MODULE,
            providerID: chosen.providerID,
            modelID: chosen.modelID,
          },
        )
        if (!report.accepted) {
          return this.failClosed(
            "Quartermaster did not accept the exact-model rate-limit report, so no replacement model was called.",
            chosen.model,
          )
        }
        blocked = { providerID: chosen.providerID, modelID: chosen.modelID }
        continue
      }
      return this.conclude(response, selectedConfig, envelope, attempt, escalation)
    }
    return this.failClosed("Quartermaster module routing stopped without a System One decision.")
  }

  private async runReview(
    envelope: ReviewEnvelope,
    attempt: ReviewAttempt,
    escalation: ReasoningEscalation | undefined,
  ): Promise<ReviewExecutionResult> {
    const started = performance.now()
    let reviewerModel = this.config.model
    try {
      const evidence = buildEvidenceResult(envelope, this.config)
      envelope.actionEvidenceComplete =
        envelope.actionEvidenceComplete !== false && evidence.actionEvidenceComplete
      const state: SystemOneState = {
        trustedPolicy: {
          reviewer: REVIEWER_SYSTEM_PROMPT,
          tenant: redactSecrets(this.config.policy ?? DEFAULT_TENANT_POLICY),
        },
        untrustedEvidence: evidence.text,
      }
      if (this.config.moduleRoutingRejected) {
        return this.failClosed(
          "Trusted Quartermaster module routing configuration is invalid, so the direct Jev transport was not called.",
        )
      }
      if (this.config.moduleRouting) {
        Object.freeze(state.trustedPolicy)
        Object.freeze(state)
        return await this.reviewRouted(state, envelope, attempt, escalation, (model) => {
          reviewerModel = model
        })
      }
      const response = await attempt.wait(
        (this.invoke ?? createSystemOneInvoker(this.config))(state, attempt.signal),
      )
      return await this.conclude(response, this.config, envelope, attempt, escalation)
    } catch (error) {
      return applyEscalationDisposition(
        {
          kind: "escalate",
          reason: formatFailureReason("System One reviewer", error),
          decisionSource: "failure-safe",
          reviewerModel,
        },
        this.config,
        "reviewer-failure",
      )
    } finally {
      const elapsed = performance.now() - started
      envelope.timings = { ...envelope.timings, reviewerMs: elapsed }
      this.recordReviewerMs?.(envelope, elapsed)
    }
  }
}
