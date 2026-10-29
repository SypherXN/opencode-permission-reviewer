import { createHash } from "node:crypto"
import { splitModel } from "../config.ts"
import { MODULE_RPC_TIMEOUT_MS, type ModuleLogger } from "./module-routing.ts"

/** Host plugin id. Quartermaster treats this as a self-reported label. */
export const DIRECT_USAGE_PLUGIN_ID = "opencode-permission-reviewer"
export const DIRECT_USAGE_PLUGIN_NAME = "OPR"

const USAGE_ID_MAX = 128
const MODEL_ID_MAX = 256
const VARIANT_MAX = 128

/**
 * Local description of Quartermaster's direct-usage method. A System One call
 * never becomes a host step, so this is the only record of its token counts.
 */
export const DirectUsageRpc = {
  id: "quartermaster",
  methods: {
    reportDirectUsage: {
      input: {
        type: "object",
        properties: {
          pluginID: { type: "string" },
          pluginName: { type: "string" },
          usageID: { type: "string" },
          providerID: { type: "string" },
          modelID: { type: "string" },
          variant: { type: "string" },
          counts: {
            type: "object",
            properties: {
              input: { type: "integer", minimum: 0 },
              output: { type: "integer", minimum: 0 },
              reasoning: { type: "integer", minimum: 0 },
              cacheRead: { type: "integer", minimum: 0 },
              cacheWrite: { type: "integer", minimum: 0 },
            },
            required: ["input", "output"],
            additionalProperties: false,
          },
        },
        required: ["pluginID", "pluginName", "usageID", "providerID", "modelID", "counts"],
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

export interface DirectUsageCounts {
  input: number
  output: number
  reasoning?: number
  cacheRead?: number
  cacheWrite?: number
}

export interface DirectUsageReport {
  pluginID: typeof DIRECT_USAGE_PLUGIN_ID
  pluginName: typeof DIRECT_USAGE_PLUGIN_NAME
  usageID: string
  providerID: string
  modelID: string
  variant?: string
  counts: DirectUsageCounts
}

export interface DirectUsageReporter {
  report(response: unknown, model: string, requestID: string): Promise<void>
}

export interface DirectUsageSender {
  send(report: DirectUsageReport): Promise<void>
}

/** The model a reviewer session was opened with. */
export interface ReviewerUsageModel {
  providerID: string
  modelID: string
  variant?: string
}

interface DirectUsageCaller {
  reportDirectUsage(
    input: DirectUsageReport,
    options: { signal: AbortSignal },
  ): Promise<unknown>
}

export interface DirectUsageRpcHost {
  rpc(definition: typeof DirectUsageRpc): DirectUsageCaller
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function boundedText(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= max && value === value.trim()
}

function count(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) return
  return value
}

/** Stable idempotency key. A readable id is kept; an overlong one is hashed. */
export function directUsageID(requestID: string, providerID: string, modelID: string): string | undefined {
  if (requestID.length === 0 || providerID.length === 0 || modelID.length === 0) return
  const readable = `${requestID}:${providerID}/${modelID}`
  if (boundedText(readable, USAGE_ID_MAX)) return readable
  return createHash("sha256").update(readable).digest("hex")
}

/**
 * Counts from a System One body. Cache and reasoning are omitted because this
 * API does not return them; Quartermaster then marks those fields partial.
 * The returned model id is the one the API named, with the configured id only
 * when that name is absent or too long to report.
 */
export function directUsageReport(
  response: unknown,
  configuredModel: string,
  requestID: string,
): DirectUsageReport | undefined {
  if (!isRecord(response) || !isRecord(response.usage)) return
  const input = count(response.usage.input_tokens)
  const output = count(response.usage.output_tokens)
  if (input === undefined || output === undefined) return
  let configured: { providerID: string; modelID: string }
  try {
    configured = splitModel(configuredModel)
  } catch {
    return
  }
  if (
    !boundedText(configured.providerID, MODEL_ID_MAX) ||
    !boundedText(configured.modelID, MODEL_ID_MAX)
  ) {
    return
  }
  const modelID = boundedText(response.model, MODEL_ID_MAX) ? response.model : configured.modelID
  const usageID = directUsageID(requestID, configured.providerID, modelID)
  if (!usageID) return
  return {
    pluginID: DIRECT_USAGE_PLUGIN_ID,
    pluginName: DIRECT_USAGE_PLUGIN_NAME,
    usageID,
    providerID: configured.providerID,
    modelID,
    counts: { input, output },
  }
}

/**
 * Counts from a host step event in the reviewer's isolation folder. Quartermaster
 * is not loaded there, so this is the only record of that step. The host event
 * id keys the report, so a redelivered event replaces rather than adds. Reasoning
 * and cache counts are sent only when the host gives them as whole numbers.
 */
export function stepUsageReport(
  event: unknown,
  modelFor: (sessionID: string) => ReviewerUsageModel | undefined,
): DirectUsageReport | undefined {
  if (!isRecord(event) || !isRecord(event.data)) return
  if (event.type !== "session.step.ended" && event.type !== "session.step.failed") return
  if (typeof event.id !== "string" || typeof event.data.sessionID !== "string") return
  const model = modelFor(event.data.sessionID)
  if (!model) return
  if (!boundedText(model.providerID, MODEL_ID_MAX) || !boundedText(model.modelID, MODEL_ID_MAX))
    return
  const tokens = event.data.tokens
  if (!isRecord(tokens)) return
  const input = count(tokens.input)
  const output = count(tokens.output)
  if (input === undefined || output === undefined) return
  const usageID = directUsageID(event.id, model.providerID, model.modelID)
  if (!usageID) return
  const counts: DirectUsageCounts = { input, output }
  const reasoning = count(tokens.reasoning)
  if (reasoning !== undefined) counts.reasoning = reasoning
  const cache = isRecord(tokens.cache) ? tokens.cache : {}
  const cacheRead = count(cache.read)
  if (cacheRead !== undefined) counts.cacheRead = cacheRead
  const cacheWrite = count(cache.write)
  if (cacheWrite !== undefined) counts.cacheWrite = cacheWrite
  return {
    pluginID: DIRECT_USAGE_PLUGIN_ID,
    pluginName: DIRECT_USAGE_PLUGIN_NAME,
    usageID,
    providerID: model.providerID,
    modelID: model.modelID,
    ...(boundedText(model.variant, VARIANT_MAX) ? { variant: model.variant } : {}),
    counts,
  }
}

export function createQuartermasterDirectUsageClient(
  ctx: DirectUsageRpcHost,
  timeoutMs = MODULE_RPC_TIMEOUT_MS,
  logger?: ModuleLogger,
): DirectUsageReporter & DirectUsageSender {
  const send = async (prepared: DirectUsageReport): Promise<void> => {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) return
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    try {
      const result = await ctx
        .rpc(DirectUsageRpc)
        .reportDirectUsage(prepared, { signal: controller.signal })
      const status = isRecord(result) && typeof result.status === "string" ? result.status : "invalid-response"
      logger?.("Quartermaster direct usage report", {
        usageID: prepared.usageID,
        providerID: prepared.providerID,
        modelID: prepared.modelID,
        status,
      })
    } catch (error) {
      logger?.("Quartermaster direct usage report failed", {
        usageID: prepared.usageID,
        error: String(error),
      })
    } finally {
      clearTimeout(timer)
    }
  }
  return {
    async report(response, model, requestID) {
      const prepared = directUsageReport(response, model, requestID)
      if (prepared) await send(prepared)
    },
    send,
  }
}

/** A host carries Quartermaster's bus as an `rpc` method, like the V2 plugin context. */
export function createHostDirectUsageClient(
  host: unknown,
  logger?: ModuleLogger,
): (DirectUsageReporter & DirectUsageSender) | undefined {
  if (!isRecord(host) || typeof host.rpc !== "function") return
  return createQuartermasterDirectUsageClient(host as unknown as DirectUsageRpcHost, undefined, logger)
}
