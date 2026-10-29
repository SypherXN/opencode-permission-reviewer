import { describe, expect, test } from "bun:test"
import { resolveConfig } from "../src/config.ts"
import { ReviewAttempt } from "../src/core/review-attempt.ts"
import { createV2ReviewerBackend } from "../src/opencode/v2/backend-factory.ts"
import { SystemOneReviewerBackend } from "../src/system-one/backend.ts"
import {
  createHostDirectUsageClient,
  createQuartermasterDirectUsageClient,
  directUsageReport,
  stepUsageReport,
  type DirectUsageReport,
} from "../src/system-one/direct-usage.ts"
import type { ReviewEnvelope } from "../src/types.ts"

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

function response(model = "jev-1.13-free", usage: Record<string, unknown> = { input_tokens: 11, output_tokens: 4 }) {
  return {
    model,
    answers: {
      outcome: choice("allow", ["allow", "deny", "escalate"]),
      risk_level: choice("low", ["low", "medium", "high", "critical"]),
      user_authorization: choice("high", ["high", "medium", "low", "unknown"]),
      scope_alignment: choice("aligned", ["aligned", "partial", "misaligned", "unknown"]),
      evidence_completeness: choice("sufficient", ["sufficient", "partial", "insufficient", "unknown"]),
      primary_basis: choice("authorized_routine", [
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
      ]),
      material_authorization: { type: "noul", noul: 1 },
      within_intent_scope: { type: "noul", noul: 1 },
      unauthorized_data_loss: { type: "noul", noul: 0 },
      untrusted_sensitive_disclosure: { type: "noul", noul: 0 },
      excessive_credential_access: { type: "noul", noul: 0 },
      unauthorized_security_change: { type: "noul", noul: 0 },
      unauthorized_external_mutation: { type: "noul", noul: 0 },
      essential_evidence_missing: { type: "noul", noul: 0 },
      absolute_policy_deny: { type: "noul", noul: 0 },
    },
    usage,
  }
}

function envelope(): ReviewEnvelope {
  return {
    request: {
      id: "req_direct_usage",
      sessionID: "ses_direct_usage",
      permission: "bash",
      patterns: ["printf ok"],
      metadata: { command: "printf ok" },
      always: [],
    },
    directory: "/workspace",
    worktree: "/workspace",
    transcript: "USER: Run the harmless marker command.",
    intentHistory: "Run the harmless marker command.",
    enrichment: "",
    sshAudit: [],
  }
}

describe("Quartermaster direct usage", () => {
  test("reports the API model and integer counts without cache or reasoning fields", () => {
    const report = directUsageReport(
      {
        ...response("jev-1.13", {
          input_tokens: 1200,
          output_tokens: 80,
          cache_read_input_tokens: 400,
          reasoning_tokens: 9,
        }),
      },
      "opencode/jev-1.13-free",
      "req_direct_usage",
    )
    expect(report).toEqual({
      pluginID: "opencode-permission-reviewer",
      pluginName: "OPR",
      usageID: "req_direct_usage:opencode/jev-1.13",
      providerID: "opencode",
      modelID: "jev-1.13",
      counts: { input: 1200, output: 80 },
    })
    expect(Object.keys(report?.counts ?? {})).toEqual(["input", "output"])
  })

  test("keeps an explicit zero and drops a body that has no integer counts", () => {
    expect(
      directUsageReport(response("jev-1.13-free", { input_tokens: 0, output_tokens: 0 }), "opencode/jev-1.13-free", "req"),
    ).toMatchObject({ counts: { input: 0, output: 0 } })
    for (const usage of [
      undefined,
      { output_tokens: 1 },
      { input_tokens: 1.5, output_tokens: 1 },
      { input_tokens: -1, output_tokens: 1 },
      { input_tokens: "10", output_tokens: 1 },
    ]) {
      const body = response()
      if (usage === undefined) delete (body as { usage?: unknown }).usage
      else body.usage = usage
      expect(directUsageReport(body, "opencode/jev-1.13-free", "req")).toBeUndefined()
    }
  })

  test("hashes an idempotency key that does not fit the Quartermaster field", () => {
    const usageID = directUsageReport(
      response(),
      "opencode/jev-1.13-free",
      "r".repeat(120),
    )?.usageID
    expect(usageID).toMatch(/^[0-9a-f]{64}$/)
  })

  test("a failed or unsupported report does not change the System One decision", async () => {
    const config = resolveConfig({ model: "opencode/jev-1.13-free" })
    const reports: DirectUsageReport[] = []
    const backend = new SystemOneReviewerBackend(
      config,
      undefined,
      undefined,
      async () => response(),
      undefined,
      undefined,
      undefined,
      undefined,
      {
        async report(response, model, requestID) {
          const prepared = directUsageReport(response, model, requestID)
          if (prepared) reports.push(prepared)
          throw new Error("telemetry unavailable")
        },
      },
    )
    const result = await backend.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(result.kind).toBe("allow")
    expect(result.decisionSource).toBe("system-one-reviewer")
    expect(reports).toEqual([
      {
        pluginID: "opencode-permission-reviewer",
        pluginName: "OPR",
        usageID: "req_direct_usage:opencode/jev-1.13-free",
        providerID: "opencode",
        modelID: "jev-1.13-free",
        counts: { input: 11, output: 4 },
      },
    ])

    const missed: unknown[] = []
    const thrown = new SystemOneReviewerBackend(
      resolveConfig({ model: "opencode/jev-1.13-free", escalationMode: "deny" }),
      undefined,
      undefined,
      async () => {
        throw new Error("status 429")
      },
      undefined,
      undefined,
      undefined,
      undefined,
      {
        async report(response) {
          missed.push(response)
        },
      },
    )
    const failure = await thrown.review(envelope(), new ReviewAttempt("generation", 10_000))
    expect(failure.kind).toBe("deny")
    expect(missed).toEqual([])
  })

  test("a usage report that never answers does not hold back the System One decision", async () => {
    let reported = false
    const backend = new SystemOneReviewerBackend(
      resolveConfig({ model: "opencode/jev-1.13-free" }),
      undefined,
      undefined,
      async () => response(),
      undefined,
      undefined,
      undefined,
      undefined,
      {
        report() {
          reported = true
          return new Promise<void>(() => {})
        },
      },
    )
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      const result = await Promise.race([
        backend.review(envelope(), new ReviewAttempt("generation", 10_000)),
        new Promise<"held back">((resolve) => (timer = setTimeout(() => resolve("held back"), 1_000))),
      ])
      expect(result).toMatchObject({ kind: "allow", decisionSource: "system-one-reviewer" })
      expect(reported).toBe(true)
    } finally {
      clearTimeout(timer)
    }
  })

  test("submits one direct-usage row and treats Quartermaster silence as non-fatal", async () => {
    const submitted: unknown[] = []
    const notes: unknown[] = []
    const client = createQuartermasterDirectUsageClient(
      {
        rpc: () => ({
          async reportDirectUsage(input) {
            submitted.push(input)
            return { apiVersion: 1, status: "unsupported", reasonCode: "telemetry-unavailable" }
          },
        }),
      },
      1_000,
      (_message, details) => notes.push(details),
    )
    await client.report(response("typesafe/jev"), "commandcode/typesafe/jev", "req_command")
    expect(submitted).toEqual([
      {
        pluginID: "opencode-permission-reviewer",
        pluginName: "OPR",
        usageID: "req_command:commandcode/typesafe/jev",
        providerID: "commandcode",
        modelID: "typesafe/jev",
        counts: { input: 11, output: 4 },
      },
    ])
    expect(notes).toEqual([
      {
        usageID: "req_command:commandcode/typesafe/jev",
        providerID: "commandcode",
        modelID: "typesafe/jev",
        status: "unsupported",
      },
    ])

    const hung = createQuartermasterDirectUsageClient(
      {
        rpc: () => ({
          reportDirectUsage: (_input, options) =>
            new Promise((_resolve, reject) => {
              options.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true })
            }),
        }),
      },
      20,
    )
    await hung.report(response(), "opencode/jev-1.13-free", "req_timeout")
  })

  test("a V1 host reports through its own rpc method, and a host without one reports nothing", async () => {
    const submitted: unknown[] = []
    const host = {
      directory: "/workspace",
      rpc(definition: { id: string }) {
        expect(this).toBe(host)
        expect(definition.id).toBe("quartermaster")
        return {
          async reportDirectUsage(input: unknown) {
            submitted.push(input)
            return { status: "accepted" }
          },
        }
      },
    }
    await createHostDirectUsageClient(host)?.report(response(), "opencode/jev-1.13-free", "req_v1")
    expect(submitted).toEqual([
      {
        pluginID: "opencode-permission-reviewer",
        pluginName: "OPR",
        usageID: "req_v1:opencode/jev-1.13-free",
        providerID: "opencode",
        modelID: "jev-1.13-free",
        counts: { input: 11, output: 4 },
      },
    ])
    expect(createHostDirectUsageClient({ directory: "/workspace" })).toBeUndefined()
    expect(createHostDirectUsageClient({ rpc: {} })).toBeUndefined()
    expect(createHostDirectUsageClient(undefined)).toBeUndefined()
  })

  test("the V2 backend reports a direct Jev response through Quartermaster", async () => {
    const previousKey = process.env.OPENCODE_API_KEY
    const previousFetch = globalThis.fetch
    process.env.OPENCODE_API_KEY = "synthetic-opencode-key"
    const submitted: unknown[] = []
    globalThis.fetch = (async () =>
      Response.json(response("jev-1.13-free", { input_tokens: 30, output_tokens: 6 }))) as unknown as typeof fetch
    try {
      const backend = createV2ReviewerBackend(
        {
          rpc: () => ({
            async reportDirectUsage(input: unknown) {
              submitted.push(input)
              return {
                apiVersion: 1,
                status: "accepted",
                attribution: "self-reported-unverified",
                replaced: false,
              }
            },
          }),
        } as unknown as Parameters<typeof createV2ReviewerBackend>[0],
        resolveConfig({ model: "opencode/jev-1.13-free" }),
      )
      const result = await backend.review(
        envelope(),
        new ReviewAttempt("generation", 10_000),
        {} as Parameters<typeof backend.review>[2],
      )
      expect(result.kind).toBe("allow")
      expect(submitted).toEqual([
        {
          pluginID: "opencode-permission-reviewer",
          pluginName: "OPR",
          usageID: "req_direct_usage:opencode/jev-1.13-free",
          providerID: "opencode",
          modelID: "jev-1.13-free",
          counts: { input: 30, output: 6 },
        },
      ])
    } finally {
      globalThis.fetch = previousFetch
      if (previousKey === undefined) delete process.env.OPENCODE_API_KEY
      else process.env.OPENCODE_API_KEY = previousKey
    }
  })
})

describe("reviewer step usage", () => {
  const model = { providerID: "openai", modelID: "gpt-6-luna", variant: "high" }
  const step = (tokens: unknown, overrides: Record<string, unknown> = {}) => ({
    id: "evt_1",
    type: "session.step.ended",
    created: 1,
    data: { sessionID: "ses_review", assistantMessageID: "msg_1", tokens },
    ...overrides,
  })
  const owned = (sessionID: string) => (sessionID === "ses_review" ? model : undefined)

  test("reports every whole-number count with the session model, variant, and event key", () => {
    const report = stepUsageReport(
      step({ input: 1200, output: 80, reasoning: 0, cache: { read: 512, write: 64 } }),
      owned,
    )
    expect(report).toEqual({
      pluginID: "opencode-permission-reviewer",
      pluginName: "OPR",
      usageID: "evt_1:openai/gpt-6-luna",
      providerID: "openai",
      modelID: "gpt-6-luna",
      variant: "high",
      counts: { input: 1200, output: 80, reasoning: 0, cacheRead: 512, cacheWrite: 64 },
    })
    expect(stepUsageReport(step({ input: 1, output: 2 }, { type: "session.step.failed" }), owned))
      .toMatchObject({ counts: { input: 1, output: 2 } })
  })

  test("drops unusable optional counts and ignores steps it cannot attribute", () => {
    const partial = stepUsageReport(
      step({ input: 10, output: 5, reasoning: 1.5, cache: { read: -1, write: "3" } }),
      owned,
    )
    expect(partial?.counts).toEqual({ input: 10, output: 5 })
    expect(stepUsageReport(step({ input: 10 }), owned)).toBeUndefined()
    expect(stepUsageReport(step({ input: 10, output: 5 }, { type: "session.step.started" }), owned))
      .toBeUndefined()
    expect(
      stepUsageReport(
        step({ input: 10, output: 5 }, { data: { sessionID: "ses_other", tokens: { input: 1, output: 1 } } }),
        owned,
      ),
    ).toBeUndefined()
    expect(stepUsageReport(step({ input: 10, output: 5 }, { id: "" }), owned)).toBeUndefined()
  })
})
