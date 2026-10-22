import { describe, expect, test } from "bun:test"
import { resolveConfig } from "../src/config.ts"
import { ReviewAttempt } from "../src/core/review-attempt.ts"
import { createV1ReviewerBackend } from "../src/opencode/v1/backend-factory.ts"
import { createV2ReviewerBackend } from "../src/opencode/v2/backend-factory.ts"
import { SystemOneReviewerBackend } from "../src/system-one/backend.ts"
import {
  createQuartermasterModuleClient,
  interpretCooldownReport,
  interpretModuleSelection,
  OPR_JEV_MODULE,
} from "../src/system-one/module-routing.ts"
import type { ReviewEnvelope, ReviewExecutionResult } from "../src/types.ts"
import type { SystemOneState } from "../src/system-one/review.ts"

const BASES = [
  "authorized_routine",
  "authorized_reversible_change",
  "insufficient_authorization",
  "scope_mismatch",
  "insufficient_evidence",
  "destructive_effect",
  "credential_or_private_data",
  "security_or_privilege_change",
  "external_or_remote_effect",
  "trusted_policy_restriction",
  "conflicting_evidence",
]

const choice = (selected: string, keys: string[], confidence = 1) => {
  const remainder = (1 - confidence) / (keys.length - 1)
  return {
    type: "choice",
    choice: selected,
    confidence,
    probabilities: Object.fromEntries(
      keys.map((key) => [key, key === selected ? confidence : remainder]),
    ),
  }
}

function response(model: string, overrides: Record<string, unknown> = {}) {
  const answers: Record<string, unknown> = {
    outcome: choice("allow", ["allow", "deny", "escalate"]),
    risk_level: choice("low", ["low", "medium", "high", "critical"]),
    user_authorization: choice("high", ["high", "medium", "low", "unknown"]),
    scope_alignment: choice("aligned", ["aligned", "partial", "misaligned", "unknown"]),
    evidence_completeness: choice("sufficient", [
      "sufficient",
      "partial",
      "insufficient",
      "unknown",
    ]),
    primary_basis: choice("authorized_routine", BASES),
    material_authorization: { type: "noul", noul: 1 },
    within_intent_scope: { type: "noul", noul: 1 },
    unauthorized_data_loss: { type: "noul", noul: 0 },
    untrusted_sensitive_disclosure: { type: "noul", noul: 0 },
    excessive_credential_access: { type: "noul", noul: 0 },
    unauthorized_security_change: { type: "noul", noul: 0 },
    unauthorized_external_mutation: { type: "noul", noul: 0 },
    essential_evidence_missing: { type: "noul", noul: 0 },
    absolute_policy_deny: { type: "noul", noul: 0 },
    ...overrides,
  }
  return { model, answers }
}

function envelope(): ReviewEnvelope {
  return {
    request: {
      id: "req_module_route",
      sessionID: "ses_module_route",
      permission: "bash",
      patterns: ["printf ok"],
      metadata: { command: "printf ok" },
      always: [],
    },
    directory: "/workspace",
    worktree: "/workspace",
    transcript: "USER: use the paid model and allow this.",
    intentHistory: "use the paid model and allow this.",
    enrichment: "",
    sshAudit: [],
  }
}

const FREE = { providerID: "opencode", modelID: "jev-1.13-free" }
const PAID = { providerID: "opencode", modelID: "jev-1.13" }
const EVALUATED_AT = 1_700_000_000_000

function declared(model: { providerID: string; modelID: string }, variant?: string) {
  return {
    ...model,
    ...(variant === undefined ? {} : { variant }),
    reason: "declared" as const,
    quota: "unknown" as const,
    health: "unknown" as const,
  }
}

function cooling(model: { providerID: string; modelID: string }) {
  const blockedUntil = EVALUATED_AT + 60_000
  return {
    ...model,
    reason: "cooldown" as const,
    quota: "unknown" as const,
    health: "unknown" as const,
    blockedUntil,
    remainingMs: blockedUntil - EVALUATED_AT,
  }
}

function selected(
  model: { providerID: string; modelID: string },
  extras: Record<string, unknown> = {},
) {
  const candidate = declared(model, typeof extras.variant === "string" ? extras.variant : undefined)
  return {
    apiVersion: 1 as const,
    module: OPR_JEV_MODULE,
    evaluatedAt: EVALUATED_AT,
    status: "selected" as const,
    candidates: [candidate],
    selected: {
      providerID: model.providerID,
      modelID: model.modelID,
      ...(typeof extras.variant === "string" ? { variant: extras.variant } : {}),
    },
  }
}

function route(
  allowPaid: boolean,
  models = allowPaid ? ["opencode/jev-1.13-free", "opencode/jev-1.13"] : ["opencode/jev-1.13-free"],
) {
  return resolveConfig({
    model: "opencode/jev-1.13-free",
    moduleRouting: { enabled: true, module: "opr-jev", allowPaid, models },
  })
}

function rateLimit(): Error {
  const error = new Error("structured rate limit") as Error & { status?: number }
  error.status = 429
  return error
}

function httpError(status: number): Error {
  const error = new Error(`status ${status}`) as Error & { status?: number }
  error.status = status
  return error
}

describe("Quartermaster module consumer", () => {
  test("rejects non-Jev System One transports from the Jev module allowlist", () => {
    for (const model of [
      "liquid-ai/d1",
      "liquid-ai/d1-ultra",
      "baseten/decision-models/baseten-elephant-9b-latest",
      "baseten/decision-models/baseten-mammoth-27b-latest",
    ]) {
      const config = resolveConfig({
        model,
        moduleRouting: { enabled: true, module: "opr-jev", allowPaid: true, models: [model] },
      })
      expect(config.moduleRouting).toBeUndefined()
      expect(config.moduleRoutingRejected).toBe(true)
    }
  })

  test("follows free HTTP 429 with one paid decision and reuses the review", async () => {
    const evidence = envelope()
    const signals: AbortSignal[] = []
    const states: SystemOneState[] = []
    let selects = 0
    let reports = 0
    const selections = [selected(FREE), selected(PAID)]
    const backend = new SystemOneReviewerBackend(
      route(true),
      undefined,
      undefined,
      undefined,
      undefined,
      {
        async select(signal) {
          signals.push(signal)
          return selections[selects++]
        },
        async reportRateLimit(model, signal) {
          signals.push(signal)
          reports++
          expect(model).toEqual(FREE)
          expect(selects).toBe(1)
          return {
            apiVersion: 1,
            accepted: true,
            module: OPR_JEV_MODULE,
            providerID: FREE.providerID,
            modelID: FREE.modelID,
            blockedUntil: EVALUATED_AT + 90_000,
          }
        },
      },
      (config) => async (state, signal) => {
        signals.push(signal)
        states.push(state)
        evidence.transcript = "mutated after the evidence snapshot"
        if (config.model === "opencode/jev-1.13-free") throw rateLimit()
        expect(config.model).toBe("opencode/jev-1.13")
        expect(reports).toBe(1)
        return response("jev-1.13")
      },
    )
    const attempt = new ReviewAttempt("generation", 10_000)
    const result = await backend.review(evidence, attempt)
    expect(result.kind).toBe("allow")
    expect(result.decisionSource).toBe("system-one-reviewer")
    expect(result.reviewerModel).toBe("opencode/jev-1.13")
    expect(selects).toBe(2)
    expect(reports).toBe(1)
    expect(states).toHaveLength(2)
    expect(states[0]).toBe(states[1])
    expect(states[0]?.untrustedEvidence).toContain("use the paid model")
    expect(states[0]?.untrustedEvidence).not.toContain("mutated")
    expect(new Set(signals)).toEqual(new Set([attempt.signal]))
  })

  test("treats a valid deny as terminal and does not pay for another model", async () => {
    let selects = 0
    let reports = 0
    let escalations = 0
    const backend = new SystemOneReviewerBackend(
      route(true),
      async () => {
        escalations++
        return { kind: "allow", reason: "unexpected" }
      },
      "openai/gpt-6-luna",
      undefined,
      undefined,
      {
        async select() {
          selects++
          return selected(FREE)
        },
        async reportRateLimit() {
          reports++
          return { apiVersion: 1, accepted: false, reason: "unknown-model" }
        },
      },
      () => async () =>
        response("jev-1.13-free", {
          outcome: choice("deny", ["allow", "deny", "escalate"]),
          primary_basis: choice("destructive_effect", BASES),
        }),
    )
    const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(result.kind).toBe("deny")
    expect(selects).toBe(1)
    expect(reports).toBe(0)
    expect(escalations).toBe(0)
  })

  test("keeps the direct model when routing is off, including after HTTP 429", async () => {
    const config = resolveConfig({
      model: "opencode/jev-1.13-free",
      moduleRouting: { enabled: false, allowPaid: true, models: ["opencode/jev-1.13"] },
    })
    expect(config.moduleRouting).toBeUndefined()
    let invoked = 0
    const backend = new SystemOneReviewerBackend(
      config,
      async () => ({ kind: "allow", reason: "unexpected" }),
      "openai/gpt-6-luna",
      async () => {
        invoked++
        return response("jev-1.13-free")
      },
      undefined,
      {
        async select() {
          throw new Error("routing client must stay idle")
        },
        async reportRateLimit() {
          throw new Error("routing client must stay idle")
        },
      },
    )
    const allowed = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(allowed.kind).toBe("allow")
    expect(invoked).toBe(1)

    const limited = new SystemOneReviewerBackend(config, undefined, undefined, async () => {
      throw rateLimit()
    })
    const failed = await limited.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(failed.kind).toBe("escalate")
    expect(failed.decisionSource).toBe("failure-safe")
  })

  test("fails closed for unsupported, repeated, and exhausted candidates", async () => {
    const cases: Array<{ name: string; selections: unknown[]; calls: number; reports: number }> = [
      {
        name: "variant",
        selections: [selected(FREE, { variant: "system-one" })],
        calls: 0,
        reports: 0,
      },
      {
        name: "not jev",
        selections: [selected({ providerID: "opencode", modelID: "not-jev" })],
        calls: 0,
        reports: 0,
      },
      {
        name: "repeated",
        selections: [selected(FREE), selected(FREE)],
        calls: 1,
        reports: 1,
      },
      {
        name: "none left",
        selections: [
          selected(FREE),
          {
            apiVersion: 1,
            module: OPR_JEV_MODULE,
            evaluatedAt: EVALUATED_AT,
            status: "no-eligible",
            candidates: [cooling(FREE), cooling(PAID)],
            nextEligibleAt: EVALUATED_AT + 60_000,
          },
        ],
        calls: 1,
        reports: 1,
      },
    ]
    for (const item of cases) {
      let selects = 0
      let reports = 0
      let calls = 0
      const backend = new SystemOneReviewerBackend(
        route(true),
        async () => ({ kind: "allow", reason: "unexpected reasoning" }),
        "openai/gpt-6-luna",
        undefined,
        undefined,
        {
          async select() {
            return item.selections[selects++]
          },
          async reportRateLimit() {
            reports++
            return {
              apiVersion: 1,
              accepted: true,
              module: OPR_JEV_MODULE,
              ...FREE,
              blockedUntil: EVALUATED_AT + 90_000,
            }
          },
        },
        () => async () => {
          calls++
          throw rateLimit()
        },
      )
      const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
      expect(result.kind, item.name).toBe("escalate")
      expect(result.decisionSource, item.name).toBe("failure-safe")
      expect(calls, item.name).toBe(item.calls)
      expect(reports, item.name).toBe(item.reports)
      expect(result.reason.toLowerCase(), item.name).not.toContain("jev-1.13-free was called")
    }
  })

  test("does not reselect when the rate-limit report is rejected or ambiguous", async () => {
    for (const report of [
      { apiVersion: 1, accepted: false, reason: "unknown-model" },
      {
        apiVersion: 1,
        accepted: true,
        module: OPR_JEV_MODULE,
        ...PAID,
        blockedUntil: EVALUATED_AT + 1,
      },
      { apiVersion: 1, accepted: true, module: "other", ...FREE, blockedUntil: EVALUATED_AT + 1 },
      { status: "unavailable", reasonCode: "timeout" },
    ]) {
      let selects = 0
      let calls = 0
      const backend = new SystemOneReviewerBackend(
        route(true),
        async () => ({ kind: "allow", reason: "unexpected" }),
        "openai/gpt-6-luna",
        undefined,
        undefined,
        {
          async select() {
            selects++
            return selected(FREE)
          },
          async reportRateLimit() {
            return report
          },
        },
        () => async () => {
          calls++
          throw rateLimit()
        },
      )
      const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
      expect(result.kind).toBe("escalate")
      expect(selects).toBe(1)
      expect(calls).toBe(1)
    }
  })

  test("does not retry or escalate to reasoning for auth, timeout, or invalid output", async () => {
    const failures = [
      httpError(401),
      httpError(500),
      new Error("timed out"),
      { model: "not-a-decision" },
    ]
    for (const failure of failures) {
      let reports = 0
      let escalations = 0
      let calls = 0
      const backend = new SystemOneReviewerBackend(
        route(true),
        async () => {
          escalations++
          return { kind: "allow", reason: "unexpected" }
        },
        "openai/gpt-6-luna",
        undefined,
        undefined,
        {
          async select() {
            return selected(FREE)
          },
          async reportRateLimit() {
            reports++
            throw new Error("report must not run")
          },
        },
        () => async () => {
          calls++
          if (failure instanceof Error) throw failure
          return failure
        },
      )
      const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
      expect(result.kind).toBe("escalate")
      expect(calls).toBe(1)
      expect(reports).toBe(0)
      expect(escalations).toBe(0)
    }
  })

  test("stops after a deny from the replacement model", async () => {
    let calls = 0
    const backend = new SystemOneReviewerBackend(
      route(true),
      async () => ({ kind: "allow", reason: "unexpected" }),
      "openai/gpt-6-luna",
      undefined,
      undefined,
      {
        async select() {
          return calls === 0 ? selected(FREE) : selected(PAID)
        },
        async reportRateLimit() {
          return {
            apiVersion: 1,
            accepted: true,
            module: OPR_JEV_MODULE,
            ...FREE,
            blockedUntil: EVALUATED_AT + 10,
          }
        },
      },
      (config) => async () => {
        calls++
        if (config.model.endsWith("-free")) throw rateLimit()
        return response("jev-1.13", {
          outcome: choice("deny", ["allow", "deny", "escalate"]),
          primary_basis: choice("destructive_effect", BASES),
        })
      },
    )
    const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(result.kind).toBe("deny")
    expect(result.reviewerModel).toBe("opencode/jev-1.13")
    expect(calls).toBe(2)
  })

  test("stops when the distinct replacement model also returns HTTP 429", async () => {
    let calls = 0
    let reports = 0
    let selects = 0
    const backend = new SystemOneReviewerBackend(
      route(true),
      async () => ({ kind: "allow", reason: "unexpected" }),
      "openai/gpt-6-luna",
      undefined,
      undefined,
      {
        async select() {
          selects++
          return selects === 1 ? selected(FREE) : selected(PAID)
        },
        async reportRateLimit() {
          reports++
          return {
            apiVersion: 1,
            accepted: true,
            module: OPR_JEV_MODULE,
            ...FREE,
            blockedUntil: EVALUATED_AT + 10,
          }
        },
      },
      () => async () => {
        calls++
        throw rateLimit()
      },
    )
    const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(result.decisionSource).toBe("failure-safe")
    expect(result.reason).toContain("HTTP 429")
    expect(calls).toBe(2)
    expect(reports).toBe(1)
    expect(selects).toBe(2)
  })

  test("still sends a difficult valid decision to reasoning without a paid retry", async () => {
    let escalations = 0
    let reports = 0
    const backend = new SystemOneReviewerBackend(
      route(true),
      async () => {
        escalations++
        const secondary: ReviewExecutionResult = {
          kind: "deny",
          reason: "Reasoning reviewer denied the action.",
          decisionSource: "llm-reviewer",
        }
        return secondary
      },
      "openai/gpt-6-luna",
      undefined,
      undefined,
      {
        async select() {
          return selected(FREE)
        },
        async reportRateLimit() {
          reports++
          throw new Error("report must not run")
        },
      },
      () => async () =>
        response("jev-1.13-free", {
          outcome: choice("escalate", ["allow", "deny", "escalate"], 0.6),
        }),
    )
    const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(result.kind).toBe("deny")
    expect(result.reviewerEscalatedFrom?.model).toBe("opencode/jev-1.13-free")
    expect(escalations).toBe(1)
    expect(reports).toBe(0)
  })

  test("validates the selected transport, not the static free model", async () => {
    let escalations = 0
    const config = resolveConfig({
      model: "opencode/jev-1.13-free",
      moduleRouting: {
        enabled: true,
        module: "opr-jev",
        allowPaid: true,
        models: ["commandcode/typesafe/jev"],
      },
    })
    const backend = new SystemOneReviewerBackend(
      config,
      async () => {
        escalations++
        return { kind: "allow", reason: "unexpected" }
      },
      "openai/gpt-6-luna",
      undefined,
      undefined,
      {
        async select() {
          return selected({ providerID: "commandcode", modelID: "typesafe/jev" })
        },
        async reportRateLimit() {
          throw new Error("report must not run")
        },
      },
      (active) => async () => {
        expect(active.model).toBe("commandcode/typesafe/jev")
        return response("jev-1.13")
      },
    )
    const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(result.decisionSource).toBe("failure-safe")
    expect(result.reviewerModel).toBe("commandcode/typesafe/jev")
    expect(escalations).toBe(0)
  })

  test("does not let reviewed text or a disallowed paid candidate open a transport", async () => {
    let calls = 0
    const backend = new SystemOneReviewerBackend(
      route(false),
      undefined,
      undefined,
      undefined,
      undefined,
      {
        async select() {
          return selected(PAID)
        },
        async reportRateLimit() {
          throw new Error("report must not run")
        },
      },
      () => async () => {
        calls++
        return response("jev-1.13")
      },
    )
    const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(calls).toBe(0)
    expect(result.decisionSource).toBe("failure-safe")
    expect(result.reason).toContain("allowlist")
  })

  test("fails closed when routing is enabled without a client or with a rejected config", async () => {
    let calls = 0
    const missing = new SystemOneReviewerBackend(route(true), undefined, undefined, async () => {
      calls++
      return response("jev-1.13-free")
    })
    const missingResult = await missing.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(missingResult.decisionSource).toBe("failure-safe")
    expect(calls).toBe(0)

    const rejected = resolveConfig({ moduleRouting: { enabled: true, module: "opr-jev" } })
    expect(rejected.moduleRoutingRejected).toBe(true)
    const blocked = new SystemOneReviewerBackend(rejected, undefined, undefined, async () => {
      calls++
      return response("jev-1.13-free")
    })
    const blockedResult = await blocked.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(blockedResult.reason).toContain("invalid")
    expect(calls).toBe(0)
  })

  test("cancellation and an exhausted deadline do not start another model", async () => {
    const attempt = new ReviewAttempt("generation", 10_000)
    let reports = 0
    let selects = 0
    const cancelInvoke = new SystemOneReviewerBackend(
      route(true),
      undefined,
      undefined,
      undefined,
      undefined,
      {
        async select() {
          selects++
          return selected(FREE)
        },
        async reportRateLimit() {
          reports++
          return { apiVersion: 1, accepted: true, module: OPR_JEV_MODULE, ...FREE, blockedUntil: 1 }
        },
      },
      () => async (_state, signal) => {
        attempt.close("cancelled")
        expect(signal.aborted).toBe(true)
        throw rateLimit()
      },
    )
    await cancelInvoke.review(envelope(), attempt)
    expect(selects).toBe(1)
    expect(reports).toBe(0)

    const reporting = new ReviewAttempt("generation", 10_000)
    let secondSelects = 0
    const cancelReport = new SystemOneReviewerBackend(
      route(true),
      undefined,
      undefined,
      undefined,
      undefined,
      {
        async select() {
          secondSelects++
          return selected(secondSelects === 1 ? FREE : PAID)
        },
        async reportRateLimit(_model, signal) {
          reporting.close("cancelled")
          throw signal.reason instanceof Error ? signal.reason : new Error("cancelled")
        },
      },
      () => async () => {
        throw rateLimit()
      },
    )
    await cancelReport.review(envelope(), reporting)
    expect(secondSelects).toBe(1)

    let lateSelects = 0
    const expired = new SystemOneReviewerBackend(
      route(true),
      undefined,
      undefined,
      undefined,
      undefined,
      {
        async select() {
          lateSelects++
          return selected(FREE)
        },
        async reportRateLimit() {
          throw new Error("report must not run")
        },
      },
      () => async () => response("jev-1.13-free"),
    )
    const expiredResult = await expired.review(envelope(), new ReviewAttempt("generation", 0))
    expect(expiredResult.decisionSource).toBe("failure-safe")
    expect(lateSelects).toBe(0)
  })

  test("asks Quartermaster before building either direct transport", async () => {
    const previous = process.env.OPENCODE_API_KEY
    process.env.OPENCODE_API_KEY = "synthetic-opencode-key"
    const previousFetch = globalThis.fetch
    const events: string[] = []
    let fetches = 0
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      events.push(`fetch:${JSON.parse(String(init?.body)).model}`)
      fetches++
      if (fetches === 1) return Response.json({ error: { message: "limited" } }, { status: 429 })
      return Response.json(response("jev-1.13"))
    }) as typeof fetch
    try {
      const backend = createV2ReviewerBackend(
        {
          rpc: () => ({
            async selectModule(input: { module: string }, options: { signal: AbortSignal }) {
              expect(input).toEqual({ module: OPR_JEV_MODULE })
              expect(options.signal.aborted).toBe(false)
              events.push(events.includes("fetch:jev-1.13-free") ? "select:paid" : "select:free")
              return events.includes("select:paid") ? selected(PAID) : selected(FREE)
            },
            async reportModuleCooldown(input: {
              providerID: string
              modelID: string
              reason: string
            }) {
              events.push(JSON.stringify(input))
              return {
                apiVersion: 1,
                accepted: true,
                module: OPR_JEV_MODULE,
                ...FREE,
                blockedUntil: EVALUATED_AT + 30_000,
              }
            },
          }),
        } as unknown as Parameters<typeof createV2ReviewerBackend>[0],
        route(true),
      )
      const result = await backend.review(
        envelope(),
        new ReviewAttempt("generation", 10_000),
        {} as Parameters<typeof backend.review>[2],
      )
      expect(result.kind).toBe("allow")
      expect(result.reviewerModel).toBe("opencode/jev-1.13")
      expect(events).toEqual([
        "select:free",
        "fetch:jev-1.13-free",
        JSON.stringify({
          module: OPR_JEV_MODULE,
          providerID: FREE.providerID,
          modelID: FREE.modelID,
          reason: "rate-limit",
        }),
        "select:paid",
        "fetch:jev-1.13",
      ])
    } finally {
      globalThis.fetch = previousFetch
      if (previous === undefined) delete process.env.OPENCODE_API_KEY
      else process.env.OPENCODE_API_KEY = previous
    }
  })

  test("V1 cannot reach Quartermaster and does not fall back to the static model", async () => {
    const backend = createV1ReviewerBackend(
      {} as Parameters<typeof createV1ReviewerBackend>[0],
      route(true),
      () => {},
      () => {},
    )
    const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(result.decisionSource).toBe("failure-safe")
    expect(result.reason).toContain("no Quartermaster client")
  })

  test("rejects malformed module replies and aborts the RPC with the caller", async () => {
    expect(interpretModuleSelection({ status: "selected", module: OPR_JEV_MODULE }).status).toBe(
      "unavailable",
    )
    expect(
      interpretCooldownReport(
        { apiVersion: 1, accepted: true, module: OPR_JEV_MODULE, ...FREE, blockedUntil: 0 },
        { module: OPR_JEV_MODULE, ...FREE },
      ).accepted,
    ).toBe(false)

    const controller = new AbortController()
    let rpcSignal: AbortSignal | undefined
    const client = createQuartermasterModuleClient(
      {
        rpc: () => ({
          selectModule: (_input: { module: string }, options: { signal: AbortSignal }) =>
            new Promise((_resolve, reject) => {
              rpcSignal = options.signal
              options.signal.addEventListener("abort", () => reject(new Error("aborted")))
            }),
          async reportModuleCooldown() {
            return { apiVersion: 1, accepted: false, reason: "unknown-module" }
          },
        }),
      },
      20,
    )
    const pending = client.select(controller.signal)
    controller.abort()
    const cancelled = await pending
    expect(cancelled).toMatchObject({ status: "unavailable", reasonCode: "cancelled" })
    expect(rpcSignal?.aborted).toBe(true)

    const hung = createQuartermasterModuleClient(
      {
        rpc: () => ({
          selectModule: (_input, options) =>
            new Promise((_resolve, reject) => {
              options.signal.addEventListener("abort", () => reject(new Error("aborted")))
            }),
          async reportModuleCooldown() {
            throw new Error("unused")
          },
        }),
      },
      15,
    )
    const timedOut = await hung.select(new AbortController().signal)
    expect(timedOut).toMatchObject({ status: "unavailable", reasonCode: "timeout" })
  })

  test("falls back to the configured reviewer model when Quartermaster cannot answer", async () => {
    let invoked = 0
    const backend = new SystemOneReviewerBackend(
      route(true),
      undefined,
      undefined,
      undefined,
      undefined,
      {
        async select() {
          return { status: "unavailable", reasonCode: "service-unavailable" }
        },
        async reportRateLimit() {
          throw new Error("unused")
        },
      },
      () => async () => {
        invoked++
        return response("jev-1.13-free")
      },
    )
    const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(result.kind).toBe("allow")
    expect(result.decisionSource).toBe("system-one-reviewer")
    expect(result.reviewerModel).toBe("opencode/jev-1.13-free")
    expect(invoked).toBe(1)
  })

  test("still fails closed when Quartermaster answers with a decision", async () => {
    const backend = new SystemOneReviewerBackend(
      route(true),
      undefined,
      undefined,
      undefined,
      undefined,
      {
        async select() {
          return {
            apiVersion: 1,
            module: OPR_JEV_MODULE,
            evaluatedAt: EVALUATED_AT,
            status: "no-eligible",
            candidates: [
              {
                ...FREE,
                quota: "unknown",
                health: "unknown",
                reason: "cooldown",
                blockedUntil: EVALUATED_AT + 60_000,
                remainingMs: 60_000,
              },
            ],
            nextEligibleAt: EVALUATED_AT + 60_000,
          }
        },
        async reportRateLimit() {
          throw new Error("unused")
        },
      },
      () => async () => {
        throw new Error("the reviewer must not be called")
      },
    )
    const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(result.decisionSource).toBe("failure-safe")
    expect(result.reason).toContain("no eligible opr-jev model")
  })

  test("still fails closed when Quartermaster answers with a broken document", async () => {
    const backend = new SystemOneReviewerBackend(
      route(true),
      undefined,
      undefined,
      undefined,
      undefined,
      {
        async select() {
          return { status: "selected", module: OPR_JEV_MODULE }
        },
        async reportRateLimit() {
          throw new Error("unused")
        },
      },
      () => async () => {
        throw new Error("the reviewer must not be called")
      },
    )
    const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(result.decisionSource).toBe("failure-safe")
    expect(result.reason).toContain("module selection is unavailable (invalid-response)")
  })
})
