import { randomBytes } from "node:crypto"
import { stat } from "node:fs/promises"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import type { OpenCodeClient } from "@opencode/client"
import type { Plugin } from "@opencode/plugin"
import { z } from "zod"
import type { ReviewAttempt } from "../../core/review-attempt.ts"
import type {
  ReviewDecision,
  ReviewEnvelope,
  ReviewExecutionResult,
  ReviewerConfig,
} from "../../types.ts"
import { buildEvidenceResult } from "../../context.ts"
import { buildReviewerPrompt, DEFAULT_TENANT_POLICY, REVIEWER_SYSTEM_PROMPT } from "../../policy.ts"
import { enforceDecision, parseDecision, parseDecisionFromText } from "../../decision.ts"
import { applyEscalationDisposition } from "../../escalation.ts"
import { formatFailureReason } from "../../failure-reason.ts"
import { DEFAULT_CONFIG, splitModel } from "../../config.ts"
import { sameIsolationDirectory } from "./in-process-client.ts"
import { createIsolatedLocation } from "./isolated-location.ts"
import { selectPlanModel } from "./plan-routing.ts"
import { captureRequestTools } from "./request-diagnostics.ts"

type Context = Parameters<Plugin.Plugin["setup"]>[0]
const TOOL = "permission_reviewer_result"
const resultSchema = z
  .object({
    version: z.literal(2),
    outcome: z.enum(["allow", "deny", "escalate"]),
    risk_level: z.enum(["low", "medium", "high", "critical"]),
    user_authorization: z.enum(["high", "medium", "low", "unknown"]),
    scope_alignment: z.enum(["aligned", "partial", "misaligned", "unknown"]),
    evidence_completeness: z.enum(["sufficient", "partial", "insufficient", "unknown"]),
    rationale: z.string().min(3).max(2000),
    confidence: z.number().min(0).max(1),
    script_analysis: z.string().min(20).max(1500).optional(),
  })
  .strict()

interface PendingGeneration {
  attempt: ReviewAttempt
  prompt: string
  structured: boolean
  results: ReviewDecision[]
  closing?: boolean
}

interface ReviewerLocation {
  directory: string
  dispose(): Promise<void>
  release(): void
}

function errorMark(error: unknown): string {
  const seen = new Set<unknown>()
  const label = (value: unknown, depth: number): string | undefined => {
    if (depth > 4 || typeof value !== "object" || value === null || seen.has(value)) return
    seen.add(value)
    const record = value as Record<string, unknown>
    const tag = record._tag ?? record.tag ?? record.name
    if (typeof tag === "string" && tag.length > 0) return tag
    return label(record.cause, depth + 1) ?? label(record.error, depth + 1)
  }
  const message = error instanceof Error ? error.message : undefined
  const text = [label(error, 0), message].filter((item): item is string => Boolean(item)).join(": ")
  return (text || "unrecognized error").slice(0, 160)
}

function sessionNotFoundTag(tag: unknown): boolean {
  return tag === "SessionNotFoundError" || tag === "Session.NotFoundError"
}

function sessionGone(error: unknown): boolean {
  const seen = new Set<unknown>()
  const visit = (value: unknown): boolean => {
    if (typeof value !== "object" || value === null || seen.has(value)) return false
    seen.add(value)
    const record = value as Record<string, unknown>
    const tag = record._tag ?? record.tag ?? record.name
    if (sessionNotFoundTag(tag)) return true
    if (typeof record.message === "string" && /Session\.?NotFound/i.test(record.message))
      return true
    return visit(record.cause) || visit(record.error)
  }
  return visit(error)
}

/** Owns auxiliary sessions and host hooks, never operational permission replies. */
export class V2ReviewerBackend {
  private readonly sessions = new Map<string, PendingGeneration>()
  /** Finished reviews whose deletion could not be confirmed. They keep tool guards
   *  without counting as in-flight work. */
  private readonly retained = new Set<string>()
  private readonly jobs = new Set<Promise<ReviewExecutionResult>>()
  private readonly locationAbort = new AbortController()
  private locationPromise: Promise<ReviewerLocation> | undefined
  private locationGate: Promise<void> = Promise.resolve()
  private disposal?: Promise<void>
  private closing = false
  constructor(
    private readonly ctx: Context,
    private readonly config: ReviewerConfig,
  ) {}

  owns(sessionID: string): boolean {
    return this.sessions.has(sessionID) || this.retained.has(sessionID)
  }

  async register(ctx: Context = this.ctx): Promise<() => Promise<void>> {
    const registrations: Array<{ dispose(): Promise<void> }> = []
    try {
      registrations.push(
        await ctx.tool.transform((editor) =>
          editor.add({
            name: TOOL,
            description:
              "Return exactly one final permission review decision matching the required schema.",
            options: { codemode: false, permission: TOOL },
            input: resultSchema,
            execute: async (input, execution) => {
              const pending = this.sessions.get(execution.sessionID)
              if (
                this.retained.has(execution.sessionID) ||
                !pending?.attempt.active() ||
                pending.closing ||
                !pending.structured
              )
                throw new Error("Not an active structured reviewer session")
              const decision = parseDecision(input)
              if (!decision) throw new Error("Invalid review decision")
              pending.results.push(decision)
              if (pending.results.length > 1)
                throw new Error("Multiple review decisions are ambiguous")
              return { content: "Decision captured. Finish without further actions." }
            },
          }),
        ),
      )
      registrations.push(
        await ctx.session.hook("context", (event) => {
          const pending = this.sessions.get(event.sessionID)
          if (this.retained.has(event.sessionID)) throw new Error("Review no longer active")
          if (!pending) {
            delete event.tools[TOOL]
            return
          }
          if (pending.closing || !pending.attempt.active())
            throw new Error("Review no longer active")
          event.system = [
            {
              type: "text",
              text:
                REVIEWER_SYSTEM_PROMPT +
                (pending.structured
                  ? `\nReturn the decision using ${TOOL} exactly once, then stop.`
                  : ""),
            },
          ]
          event.messages = [{ role: "user", content: [{ type: "text", text: pending.prompt }] }]
          const definition = event.tools[TOOL]
          event.tools =
            pending.structured && pending.results.length === 0 && definition
              ? { [TOOL]: definition }
              : {}
        }),
      )
      if (this.config.debug) {
        registrations.push(
          await ctx.session.hook("http.request", async (event) => {
            const pending = this.sessions.get(event.sessionID)
            if (this.retained.has(event.sessionID) || !pending?.attempt.active() || pending.closing)
              return
            const capture = await captureRequestTools(event.request)
            console.error(
              "permission-reviewer request-tools " +
                JSON.stringify({
                  sessionID: event.sessionID,
                  model: event.model,
                  kind: event.kind,
                  ...capture,
                }),
            )
          }),
        )
      }
      registrations.push(
        await ctx.tool.hook("execute.before", (event) => {
          const pending = this.sessions.get(event.sessionID)
          if (
            this.retained.has(event.sessionID) ||
            (pending && (pending.closing || event.tool !== TOOL))
          ) {
            throw new Error("Operational tools are disabled in reviewer sessions")
          }
        }),
      )
      return async () => {
        await Promise.all(registrations.map((registration) => registration.dispose()))
      }
    } catch (error) {
      await Promise.allSettled(registrations.map((registration) => registration.dispose()))
      throw error
    }
  }

  review(
    envelope: ReviewEnvelope,
    attempt: ReviewAttempt,
    client: OpenCodeClient,
  ): Promise<ReviewExecutionResult> {
    if (this.closing) throw new Error("Reviewer backend is shutting down")
    if (this.sessions.size >= 64) throw new Error("Reviewer session cleanup capacity exhausted")
    const job = this.runReview(envelope, attempt, client).finally(() => this.jobs.delete(job))
    this.jobs.add(job)
    return job
  }

  async waitForIdle(): Promise<void> {
    await Promise.allSettled([...this.jobs])
  }

  dispose(): Promise<void> {
    if (this.disposal) return this.disposal
    this.closing = true
    this.locationAbort.abort(new Error("Reviewer backend is shutting down"))
    this.disposal = (async () => {
      await this.waitForIdle()
      const location = await this.locationPromise?.catch(() => undefined)
      // An uncertain session deletion must retain the guards in its cached location.
      if (!location || this.sessions.size > 0 || this.retained.size > 0) return
      try {
        await location.dispose()
      } finally {
        location.release()
      }
    })()
    return this.disposal
  }

  private ensureLocation(client: OpenCodeClient): Promise<ReviewerLocation> {
    const run = this.locationGate.then(() => this.ensureLocationLocked(client))
    this.locationGate = run.then(
      () => undefined,
      () => undefined,
    )
    return run
  }

  private async ensureLocationLocked(client: OpenCodeClient): Promise<ReviewerLocation> {
    const current = this.locationPromise
    if (current) {
      const location = await current.catch(() => undefined)
      if (this.locationPromise !== current) return this.ensureLocationLocked(client)
      // A live reviewer session still depends on this location's guards.
      if (
        location &&
        ((await isolationFilesIntact(location.directory)) || this.sessions.size > 0 || this.closing)
      )
        return location
      if (location) {
        this.locationPromise = undefined
        try {
          await location.dispose()
        } finally {
          location.release()
        }
      }
    }
    if (this.locationPromise) return this.ensureLocationLocked(client)
    return this.rememberLocation(client)
  }

  private rememberLocation(client: OpenCodeClient): Promise<ReviewerLocation> {
    const location = this.openLocation(client)
    this.locationPromise = location
    void location.catch(() => {
      if (this.locationPromise === location) this.locationPromise = undefined
    })
    return location
  }

  private async openLocation(client: OpenCodeClient): Promise<ReviewerLocation> {
    const registrations = new Set<() => Promise<void>>()
    const dispose = async () => {
      const results = await Promise.allSettled(
        [...registrations].map((registration) => registration()),
      )
      const failed = results.find((result) => result.status === "rejected")
      if (failed) throw failed.reason
    }
    const isolated = await createIsolatedLocation(async (context) => {
      if (this.closing) return async () => {}
      const cleanup = await this.register(context)
      const registration = async () => {
        if (!registrations.delete(registration)) return
        await cleanup()
      }
      registrations.add(registration)
      if (this.closing) await registration()
      return registration
    })
    try {
      // The plugin is active as soon as setup runs. The longer bound covers a
      // folder-trust dialog, which blocks that load until it is answered.
      const signal = AbortSignal.any([this.locationAbort.signal, AbortSignal.timeout(90_000)])
      await waitForIsolationActive(client, isolated.directory, isolated.pluginID, signal)
      if (registrations.size === 0) throw new Error("Reviewer isolation hooks did not activate")
      return { directory: isolated.directory, dispose, release: isolated.release }
    } catch (error) {
      await dispose().catch(() => {})
      isolated.release()
      // The host may have cached this location, so its MCP exclusion stays on disk.
      if (error instanceof Error && error.name === "TimeoutError")
        throw new Error("Reviewer isolation did not activate before the deadline", { cause: error })
      throw error
    }
  }

  private async runReview(
    envelope: ReviewEnvelope,
    attempt: ReviewAttempt,
    client: OpenCodeClient,
  ): Promise<ReviewExecutionResult> {
    const id = `ses_${randomBytes(16).toString("hex")}`
    let createIssued = false
    try {
      if (this.config.planRoutingRejected) throw new Error("Trusted planRouting config is invalid")
      const selection: { providerID: string; modelID: string; variant?: string } = this.config
        .planRouting
        ? await attempt.wait(selectPlanModel(this.ctx, this.config, attempt.signal))
        : splitModel(this.config.model)
      const { providerID, modelID } = selection
      const { directory } = await attempt.wait(this.ensureLocation(client))
      const inventory = await attempt.wait(
        client.mcp.list({ location: { directory } }, { signal: attempt.signal }),
      )
      if (inventory.location.directory !== directory)
        throw new Error("Reviewer MCP inventory belongs to another location")
      if (inventory.data.length > 0)
        throw new Error("Reviewer isolation location contains MCP servers")
      const catalog = await attempt.wait(
        client.model.list({ location: { directory } }, { signal: attempt.signal }),
      )
      const model = catalog.data.find(
        (item) => item.providerID === providerID && item.id === modelID,
      )
      if (!model) throw new Error("Reviewer model is unavailable")
      const plannedVariant = selection.variant
      if (plannedVariant && !(model.variants ?? []).some((item) => item.id === plannedVariant))
        throw new Error("Quartermaster selected an unavailable reviewer variant")
      const variant = selectVariant(
        plannedVariant ?? this.config.variant,
        (model.variants ?? []).map((item) => item.id),
      )
      if (this.config.outputFormat === "json_schema" && !model.capabilities.tools) {
        throw new Error("Reviewer model does not support structured tool output")
      }
      const evidence = buildEvidenceResult(envelope, this.config)
      envelope.actionEvidenceComplete =
        envelope.actionEvidenceComplete !== false && evidence.actionEvidenceComplete
      const pending: PendingGeneration = {
        attempt,
        prompt: buildReviewerPrompt(
          this.config.policy ?? DEFAULT_TENANT_POLICY,
          evidence.text,
          this.config.outputFormat,
        ),
        structured: this.config.outputFormat === "json_schema",
        results: [],
      }
      this.sessions.set(id, pending)
      createIssued = true
      const created = await attempt.wait(
        client.session.create(
          {
            id,
            title: "Permission review",
            location: { directory },
            model: {
              id: modelID,
              providerID,
              ...(variant ? { variant } : {}),
            },
            permissions: [
              { action: "*", resource: "*", effect: "deny" },
              ...(pending.structured
                ? [{ action: TOOL, resource: "*", effect: "allow" as const }]
                : []),
            ],
          },
          { signal: attempt.signal },
        ),
      )
      if (created.id !== id || created.location.directory !== directory)
        throw new Error("Reviewer session identity or isolation location does not match")
      const tries = pending.structured ? 3 : 2
      for (let index = 0; index < tries; index++) {
        pending.results = []
        const signal = AbortSignal.any([attempt.signal, AbortSignal.timeout(this.config.timeoutMs)])
        const admitted = await attempt.wait(
          client.session.prompt({ sessionID: id, text: pending.prompt }, { signal }),
        )
        await attempt.wait(client.session.wait({ sessionID: id }, { signal }))
        if (!attempt.active()) throw new Error("Review no longer active")
        const messages = await attempt.wait(client.session.context({ sessionID: id }, { signal }))
        // This session is exclusively owned by this attempt, with sequential prompts.
        const userIndex = messages.findIndex((message) => message.id === admitted.id)
        const response = messages
          .slice(userIndex < 0 ? messages.length : userIndex + 1)
          .filter((message) => message.type === "assistant")
        const toolMessages = response
          .map((message) => message.content.filter((part) => part.type === "tool"))
          .filter((parts) => parts.length > 0)
        const toolParts = toolMessages.flat()
        const finalTool = toolParts.at(-1)
        const boundedSchemaRetries =
          toolMessages.every((parts) => parts.length === 1) &&
          toolParts.length <= 3 &&
          toolParts
            .slice(0, -1)
            .every((part) => part.name === TOOL && part.state.status === "error")
        const ambiguous =
          pending.results.length > 1 ||
          (pending.results.length === 1 &&
            (userIndex < 0 ||
              !boundedSchemaRetries ||
              finalTool?.name !== TOOL ||
              finalTool?.state.status !== "completed"))
        const parsed = pending.structured
          ? pending.results.length === 1 && !ambiguous
            ? pending.results[0]
            : undefined
          : parseDecisionFromText(
              response
                .flatMap((message) =>
                  message.content.filter((part) => part.type === "text").map((part) => part.text),
                )
                .join("\n"),
            )
        if (ambiguous) break
        if (parsed)
          return {
            ...enforceDecision(parsed, this.config),
            reviewSessionID: id,
            decisionSource: "llm-reviewer",
            reviewerModel: `${providerID}/${modelID}`,
          }
        pending.prompt +=
          "\nThe prior response was invalid. Return exactly one valid decision using the requested format."
      }
      return applyEscalationDisposition(
        {
          kind: "escalate",
          reason: "Reviewer returned missing, invalid, or ambiguous output.",
          reviewSessionID: id,
          decisionSource: "failure-safe",
        },
        this.config,
        "invalid-decision",
      )
    } catch (error) {
      return applyEscalationDisposition(
        {
          kind: "escalate",
          reason: formatFailureReason("reviewer session call", error),
          reviewSessionID: id,
          decisionSource: "failure-safe",
        },
        this.config,
        "reviewer-failure",
      )
    } finally {
      // Keep the tool guard until interruption and deletion have settled.
      const pending = this.sessions.get(id)
      if (pending) pending.closing = true
      let cleanupConfirmed = !createIssued
      let cleanupFault = "session remained readable"
      try {
        if (createIssued) {
          for (let retry = 0; retry < 2 && !cleanupConfirmed; retry++) {
            try {
              await client.session.interrupt(
                { sessionID: id },
                { signal: AbortSignal.timeout(2000) },
              )
              if (this.config.retainReviewSessions) cleanupConfirmed = true
            } catch (error) {
              cleanupFault = errorMark(error)
              if (sessionGone(error)) cleanupConfirmed = true
            }
            if (!this.config.retainReviewSessions && !cleanupConfirmed) {
              try {
                await client.session.remove(
                  { sessionID: id },
                  { signal: AbortSignal.timeout(2000) },
                )
              } catch (error) {
                // A lost response is not proof that deletion failed or succeeded.
                cleanupFault = errorMark(error)
              }
              try {
                await client.session.get({ sessionID: id }, { signal: AbortSignal.timeout(2000) })
                cleanupFault = "session remained readable"
              } catch (error) {
                cleanupFault = errorMark(error)
                cleanupConfirmed = sessionGone(error)
              }
            }
          }
          if (!cleanupConfirmed)
            // Cleanup uncertainty must override a provisional allow; the controller fails closed.
            // eslint-disable-next-line no-unsafe-finally
            throw new Error(
              `Reviewer cleanup could not be confirmed; isolation guards remain active (${cleanupFault})`,
            )
        }
      } finally {
        // The attempt is finished. An unconfirmed session keeps its tool guard, but it
        // is no longer in-flight, so it cannot block the next review or pin a dead location.
        this.sessions.delete(id)
        if (cleanupConfirmed || !createIssued) this.retained.delete(id)
        else this.retained.add(id)
      }
    }
  }
}

/** Wait until the host reports the isolation bootstrap active for its directory.
 *
 * The client no longer offers a dedicated activation wait, so poll the plugin
 * inventory for this attempt's bootstrap entry: it is identified by its unique
 * local path, the wait ends once the host reports it active, and a reported
 * failure fails loudly. The attempt deadline still bounds the wait, and a
 * transport error rejects like any other reviewer failure.
 */
async function isolationFilesIntact(directory: string): Promise<boolean> {
  try {
    const files = await Promise.all(
      ["index.js", "package.json", "opencode.json"].map((name) => stat(join(directory, name))),
    )
    return files.every((file) => file.isFile())
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false
    throw error
  }
}

async function waitForIsolationActive(
  client: OpenCodeClient,
  directory: string,
  pluginID: string,
  signal: AbortSignal,
): Promise<void> {
  const root = resolve(directory)
  for (;;) {
    const plugins = await client.plugin.list({ location: { directory } }, { signal })
    if (
      plugins.data.some(
        (plugin) =>
          (plugin as unknown as { id?: unknown }).id === "quartermaster" &&
          plugin.state.status === "active",
      )
    )
      throw new Error("Quartermaster must be disabled in the reviewer isolation location")
    const entry = plugins.data.find((plugin) => {
      if (plugin.source.type !== "local") return false
      if ((plugin as unknown as { id?: unknown }).id === pluginID) return true
      const path = plugin.source.path
      if (typeof path !== "string") return false
      try {
        const local = path.startsWith("file:") ? fileURLToPath(path) : path
        return (
          sameIsolationDirectory(local, root) ||
          sameIsolationDirectory(local, join(root, "index.js"))
        )
      } catch {
        return false
      }
    })
    if (entry !== undefined) {
      if (entry.state.status === "active") return
      throw new Error(`Reviewer isolation failed to activate: ${entry.state.error}`)
    }
    await new Promise<void>((resolve, reject) => {
      if (signal.aborted) {
        reject(signal.reason)
        return
      }
      const onAbort = () => {
        clearTimeout(timer)
        reject(signal.reason)
      }
      const timer = setTimeout(() => {
        signal.removeEventListener("abort", onAbort)
        resolve()
      }, 100)
      signal.addEventListener("abort", onAbort, { once: true })
      if (signal.aborted) onAbort()
    })
  }
}

/** Picks the reviewer variant to request from the host catalog. The built-in
 *  default is only a preference: models that do not offer it run with their
 *  own default instead of failing every review. An explicitly configured
 *  variant the model does not offer still fails closed. */
export function selectVariant(configured: string, available: string[]): string | undefined {
  if (!configured || available.includes(configured)) return configured || undefined
  if (configured === DEFAULT_CONFIG.variant) return undefined
  throw new Error(
    `Reviewer variant "${configured}" is unavailable` +
      (available.length > 0
        ? ` (model offers: ${available.join(", ")})`
        : " (model has no variants)"),
  )
}
