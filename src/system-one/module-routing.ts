import type { ModuleRoutingConfig } from "../types.ts"
import { isFreeSystemOneModel, isSystemOneReviewerModel, splitModel } from "../config.ts"

/** Quartermaster module OPR asks for. Labels are not authenticated identities. */
export const OPR_JEV_MODULE = "opr-jev"

/** Helper budget for one module RPC. This is not the review deadline or a cooldown. */
export const MODULE_RPC_TIMEOUT_MS = 2_000

const UNAVAILABLE = [
  "timeout",
  "cancelled",
  "service-unavailable",
  "invalid-response",
  "invalid-input",
] as const

export type ModuleUnavailableReason = (typeof UNAVAILABLE)[number]

/** Debug sink for the module exchange; the audit trail keeps the reason code. */
export type ModuleLogger = (message: string, details?: unknown) => void

export interface ModuleModelRef {
  providerID: string
  modelID: string
  variant?: string
}

export interface ModuleCandidateView extends ModuleModelRef {
  reason: "declared" | "cooldown"
  quota: "unknown"
  health: "unknown"
  blockedUntil?: number
  remainingMs?: number
}

export type ModuleSelectionView = {
  apiVersion: 1
  module: string
  evaluatedAt: number
  candidates: ModuleCandidateView[]
} & (
  | { status: "selected"; selected: ModuleModelRef; nextEligibleAt?: undefined }
  | { status: "no-module"; selected?: undefined; nextEligibleAt?: undefined }
  | { status: "no-eligible"; selected?: undefined; nextEligibleAt?: number }
)

export type ModuleSelectionResult =
  ModuleSelectionView | { status: "unavailable"; reasonCode: ModuleUnavailableReason }

export type ModuleCooldownResult =
  | {
      apiVersion: 1
      accepted: true
      module: string
      providerID: string
      modelID: string
      blockedUntil: number
    }
  | { apiVersion: 1; accepted: false; reason: "unknown-module" | "unknown-model" }
  | { status: "unavailable"; accepted: false; reasonCode: ModuleUnavailableReason }

export interface ModuleRoutingClient {
  select(signal: AbortSignal): Promise<unknown>
  reportRateLimit(
    model: { providerID: string; modelID: string },
    signal: AbortSignal,
  ): Promise<unknown>
}

export interface QuartermasterModuleCaller {
  selectModule(input: { module: string }, options: { signal: AbortSignal }): Promise<unknown>
  reportModuleCooldown(
    input: {
      module: string
      providerID: string
      modelID: string
      reason: "rate-limit"
    },
    options: { signal: AbortSignal },
  ): Promise<unknown>
}

/** Local description of the two quartermaster methods OPR calls. */
export const QuartermasterModuleRpc = {
  id: "quartermaster",
  methods: {
    selectModule: {
      input: {
        type: "object",
        properties: { module: { type: "string" } },
        required: ["module"],
        additionalProperties: false,
      },
      output: { type: "object", additionalProperties: true },
      errors: {
        invalid_input: {
          type: "object",
          properties: { path: { type: "string" }, message: { type: "string" } },
          required: ["path", "message"],
          additionalProperties: false,
        },
        unavailable: {
          type: "object",
          properties: { reason: { type: "string" } },
          required: ["reason"],
          additionalProperties: false,
        },
      },
    },
    reportModuleCooldown: {
      input: {
        type: "object",
        properties: {
          module: { type: "string" },
          providerID: { type: "string" },
          modelID: { type: "string" },
          reason: { type: "string", enum: ["rate-limit", "temporary-unavailable"] },
        },
        required: ["module", "providerID", "modelID", "reason"],
        additionalProperties: false,
      },
      output: { type: "object", additionalProperties: true },
      errors: {
        invalid_input: {
          type: "object",
          properties: { path: { type: "string" }, message: { type: "string" } },
          required: ["path", "message"],
          additionalProperties: false,
        },
        unavailable: {
          type: "object",
          properties: { reason: { type: "string" } },
          required: ["reason"],
          additionalProperties: false,
        },
      },
    },
  },
  events: {},
} as const

export interface QuartermasterRpcHost {
  rpc(definition: typeof QuartermasterModuleRpc): QuartermasterModuleCaller
}

export function systemOneModelName(model: { providerID: string; modelID: string }): string {
  return `${model.providerID}/${model.modelID}`
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function nonempty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.trim() === value
}

function timestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
}

function unavailableReason(value: unknown): ModuleUnavailableReason | undefined {
  if (!isRecord(value) || value.status !== "unavailable") return
  return UNAVAILABLE.find((reason) => reason === value.reasonCode)
}

function validModel(value: unknown): value is ModuleModelRef {
  if (!isRecord(value) || !nonempty(value.providerID) || !nonempty(value.modelID)) return false
  if (value.variant !== undefined && !nonempty(value.variant)) return false
  return true
}

function sameModel(left: ModuleModelRef, right: ModuleModelRef): boolean {
  return (
    left.providerID === right.providerID &&
    left.modelID === right.modelID &&
    left.variant === right.variant
  )
}

/** Accept only the versioned module recommendation Quartermaster documents. */
export function interpretModuleSelection(value: unknown): ModuleSelectionResult {
  const reasonCode = unavailableReason(value)
  if (reasonCode) return { status: "unavailable", reasonCode }
  if (!isRecord(value) || value.apiVersion !== 1 || value.module !== OPR_JEV_MODULE) {
    return { status: "unavailable", reasonCode: "invalid-response" }
  }
  if (!timestamp(value.evaluatedAt) || !Array.isArray(value.candidates)) {
    return { status: "unavailable", reasonCode: "invalid-response" }
  }
  const seen = new Set<string>()
  for (const candidate of value.candidates) {
    if (!validModel(candidate) || !isRecord(candidate)) {
      return { status: "unavailable", reasonCode: "invalid-response" }
    }
    if (candidate.quota !== "unknown" || candidate.health !== "unknown") {
      return { status: "unavailable", reasonCode: "invalid-response" }
    }
    const key = `${candidate.providerID}\0${candidate.modelID}`
    if (seen.has(key)) return { status: "unavailable", reasonCode: "invalid-response" }
    seen.add(key)
    if (candidate.reason === "cooldown") {
      if (
        !timestamp(candidate.blockedUntil) ||
        candidate.blockedUntil <= value.evaluatedAt ||
        candidate.remainingMs !== candidate.blockedUntil - value.evaluatedAt
      ) {
        return { status: "unavailable", reasonCode: "invalid-response" }
      }
    } else if (
      candidate.reason !== "declared" ||
      candidate.blockedUntil !== undefined ||
      candidate.remainingMs !== undefined
    ) {
      return { status: "unavailable", reasonCode: "invalid-response" }
    }
  }
  const candidates = value.candidates as ModuleCandidateView[]
  const first = candidates.find((candidate) => candidate.reason === "declared")
  if (value.status === "selected") {
    if (
      !first ||
      !validModel(value.selected) ||
      !sameModel(first, value.selected) ||
      value.nextEligibleAt !== undefined
    ) {
      return { status: "unavailable", reasonCode: "invalid-response" }
    }
    return value as ModuleSelectionView
  }
  if (value.selected !== undefined) return { status: "unavailable", reasonCode: "invalid-response" }
  if (value.status === "no-module") {
    if (candidates.length !== 0 || value.nextEligibleAt !== undefined) {
      return { status: "unavailable", reasonCode: "invalid-response" }
    }
    return value as ModuleSelectionView
  }
  if (value.status !== "no-eligible" || candidates.length === 0 || first) {
    return { status: "unavailable", reasonCode: "invalid-response" }
  }
  const nextEligibleAt = candidates.reduce(
    (earliest, candidate) => Math.min(earliest, candidate.blockedUntil ?? Number.POSITIVE_INFINITY),
    Number.POSITIVE_INFINITY,
  )
  if (value.nextEligibleAt !== nextEligibleAt) {
    return { status: "unavailable", reasonCode: "invalid-response" }
  }
  return value as ModuleSelectionView
}

/** An accepted report is an exact persisted model deadline, not permission to retry twice. */
export function interpretCooldownReport(
  value: unknown,
  expected: { module: string; providerID: string; modelID: string },
): ModuleCooldownResult {
  const reasonCode = unavailableReason(value)
  if (reasonCode) return { status: "unavailable", accepted: false, reasonCode }
  if (!isRecord(value) || value.apiVersion !== 1) {
    return { status: "unavailable", accepted: false, reasonCode: "invalid-response" }
  }
  if (
    value.accepted === false &&
    (value.reason === "unknown-module" || value.reason === "unknown-model")
  ) {
    return { apiVersion: 1, accepted: false, reason: value.reason }
  }
  if (
    value.accepted === true &&
    value.module === expected.module &&
    value.providerID === expected.providerID &&
    value.modelID === expected.modelID &&
    timestamp(value.blockedUntil) &&
    value.blockedUntil > 0
  ) {
    return {
      apiVersion: 1,
      accepted: true,
      module: expected.module,
      providerID: expected.providerID,
      modelID: expected.modelID,
      blockedUntil: value.blockedUntil,
    }
  }
  return { status: "unavailable", accepted: false, reasonCode: "invalid-response" }
}

export function isStructuredRateLimit(error: unknown): boolean {
  const seen = new Set<unknown>()
  let current = error
  for (
    let depth = 0;
    depth < 4 && current && typeof current === "object" && !seen.has(current);
    depth++
  ) {
    seen.add(current)
    if ((current as { status?: unknown }).status === 429) return true
    current = (current as { cause?: unknown }).cause
  }
  return false
}

export type ModelPermitResult =
  { ok: true; providerID: string; modelID: string; model: string } | { ok: false; reason: string }

/** Policy that any model must pass before the System One transport may call it. */
export function permitModel(
  routing: ModuleRoutingConfig,
  selected: ModuleModelRef,
  blocked?: { providerID: string; modelID: string },
): ModelPermitResult {
  if (selected.variant !== undefined || !isSystemOneReviewerModel(systemOneModelName(selected))) {
    return {
      ok: false,
      reason:
        "Quartermaster selected a model the System One transport cannot use, so it was not called.",
    }
  }
  const listed = routing.models.some(
    (model) => model.providerID === selected.providerID && model.modelID === selected.modelID,
  )
  const free = isFreeSystemOneModel(selected.providerID, selected.modelID)
  if (!listed || (!free && !routing.allowPaid)) {
    return {
      ok: false,
      reason:
        "Quartermaster selected a model outside the trusted allowlist or paid-use policy, so it was not called.",
    }
  }
  if (
    blocked &&
    blocked.providerID === selected.providerID &&
    blocked.modelID === selected.modelID
  ) {
    return {
      ok: false,
      reason:
        "Quartermaster repeated a rate-limited model, so the review stopped without another call.",
    }
  }
  return {
    ok: true,
    providerID: selected.providerID,
    modelID: selected.modelID,
    model: systemOneModelName(selected),
  }
}

export function permitSelectedModel(
  routing: ModuleRoutingConfig,
  selection: ModuleSelectionResult,
  blocked?: { providerID: string; modelID: string },
): ModelPermitResult {
  if (selection.status === "unavailable") {
    return {
      ok: false,
      reason: `Quartermaster module selection is unavailable (${selection.reasonCode}), so the direct Jev transport was not called.`,
    }
  }
  if (selection.status === "no-module") {
    return {
      ok: false,
      reason:
        "Quartermaster has no opr-jev module profile, so the direct Jev transport was not called.",
    }
  }
  if (selection.status === "no-eligible") {
    return {
      ok: false,
      reason:
        "Quartermaster has no eligible opr-jev model, so the direct Jev transport was not called.",
    }
  }
  return permitModel(routing, selection.selected, blocked)
}

/**
 * Quartermaster gave no decision at all (transport failure or timeout), so there is
 * no Quartermaster decision to honour. The trusted configured reviewer model may be
 * used instead, under the same allowlist and paid-use policy.
 */
export function permitFallbackModel(
  routing: ModuleRoutingConfig,
  selection: ModuleSelectionResult,
  configuredModel: string,
  blocked?: { providerID: string; modelID: string },
): ModelPermitResult {
  if (selection.status !== "unavailable") return { ok: false, reason: "Quartermaster answered" }
  if (selection.reasonCode !== "service-unavailable" && selection.reasonCode !== "timeout") {
    return { ok: false, reason: "Quartermaster did not fail to answer" }
  }
  let configured: ModuleModelRef
  try {
    configured = splitModel(configuredModel)
  } catch {
    return { ok: false, reason: "The configured reviewer model is not a valid model reference" }
  }
  return permitModel(routing, configured, blocked)
}

async function callModuleMethod(
  invoke: (signal: AbortSignal) => Promise<unknown>,
  timeoutMs: number,
  signal: AbortSignal,
  logger?: ModuleLogger,
): Promise<unknown> {
  if (signal.aborted) return { status: "unavailable", reasonCode: "cancelled" }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2_147_483_647) {
    return { status: "unavailable", reasonCode: "invalid-input" }
  }
  const controller = new AbortController()
  let reasonCode: ModuleUnavailableReason = "service-unavailable"
  let timer: ReturnType<typeof setTimeout> | undefined
  const abortFromCaller = () => controller.abort()
  try {
    signal.addEventListener("abort", abortFromCaller, { once: true })
    timer = setTimeout(() => {
      reasonCode = "timeout"
      controller.abort()
    }, timeoutMs)
    const result = await invoke(controller.signal)
    if (signal.aborted) return { status: "unavailable", reasonCode: "cancelled" }
    if (controller.signal.aborted) return { status: "unavailable", reasonCode }
    return result
  } catch (error) {
    // A timeout is Quartermaster not answering. Any other throw is a broken
    // call, not permission to use the configured model.
    const code = signal.aborted
      ? "cancelled"
      : controller.signal.aborted
        ? reasonCode
        : "invalid-response"
    logger?.("Quartermaster module RPC failed", { reasonCode: code, error: String(error) })
    return {
      status: "unavailable",
      reasonCode: code,
    }
  } finally {
    clearTimeout(timer)
    signal.removeEventListener("abort", abortFromCaller)
  }
}

export function createQuartermasterModuleClient(
  ctx: QuartermasterRpcHost,
  timeoutMs = MODULE_RPC_TIMEOUT_MS,
  logger?: ModuleLogger,
): ModuleRoutingClient {
  return {
    async select(signal) {
      const result = await callModuleMethod(
        (rpcSignal) =>
          ctx
            .rpc(QuartermasterModuleRpc)
            .selectModule({ module: OPR_JEV_MODULE }, { signal: rpcSignal }),
        timeoutMs,
        signal,
        logger,
      )
      const interpreted = interpretModuleSelection(result)
      logger?.("Quartermaster module selection", {
        raw: result,
        outcome: interpreted.status === "unavailable" ? interpreted.reasonCode : interpreted.status,
      })
      return interpreted
    },
    async reportRateLimit(model, signal) {
      const expected = {
        module: OPR_JEV_MODULE,
        providerID: model.providerID,
        modelID: model.modelID,
      }
      const result = await callModuleMethod(
        (rpcSignal) =>
          ctx
            .rpc(QuartermasterModuleRpc)
            .reportModuleCooldown({ ...expected, reason: "rate-limit" }, { signal: rpcSignal }),
        timeoutMs,
        signal,
        logger,
      )
      const interpreted = interpretCooldownReport(result, expected)
      logger?.("Quartermaster module cooldown report", {
        raw: result,
        outcome: "status" in interpreted ? interpreted.reasonCode : interpreted.accepted,
      })
      return interpreted
    },
  }
}
