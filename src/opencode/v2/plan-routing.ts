import type { Plugin } from "@opencode/plugin"
import type { ReviewerConfig } from "../../types.ts"
import { splitModel } from "../../config.ts"

type Context = Parameters<Plugin.Plugin["setup"]>[0]

/** Wire-compatible subset: no runtime dependency on a private QM checkout. */
const PlanRpc = {
  id: "quartermaster",
  methods: {
    selectPlan: {
      input: {
        type: "object",
        properties: { plan: { type: "string" } },
        required: ["plan"],
        additionalProperties: false,
      },
      output: { type: "object", additionalProperties: true },
      errors: {},
    },
  },
  events: {},
} as const

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

export async function selectPlanModel(
  ctx: Pick<Context, "rpc">,
  config: ReviewerConfig,
  signal: AbortSignal,
  timeoutMs = 2000,
): Promise<{ providerID: string; modelID: string; variant?: string }> {
  const route = config.planRouting
  if (!route) throw new Error("Missing trusted planRouting config")
  signal.throwIfAborted()
  const controller = new AbortController()
  let reject!: (error: Error) => void
  const interrupted = new Promise<never>((_, fail) => {
    reject = fail
  })
  const abort = () => {
    controller.abort()
    reject(new Error("Quartermaster plan selection cancelled"))
  }
  signal.addEventListener("abort", abort, { once: true })
  const timer = setTimeout(() => {
    controller.abort()
    reject(new Error("Quartermaster plan selection timed out"))
  }, timeoutMs)
  try {
    const result: unknown = await Promise.race([
      ctx.rpc(PlanRpc).selectPlan({ plan: route.plan }, { signal: controller.signal }),
      interrupted,
    ])
    if (
      !record(result) ||
      result.apiVersion !== 1 ||
      typeof result.reasonCode !== "string" ||
      typeof result.reason !== "string" ||
      !Array.isArray(result.skipped)
    )
      throw new Error("Invalid Quartermaster plan response")
    if (result.status !== "selected") throw new Error("Quartermaster plan has no selected model")
    if (
      !record(result.plan) ||
      result.plan.id !== route.plan ||
      result.plan.source !== "named-plan" ||
      typeof result.plan.reasonCode !== "string"
    ) {
      throw new Error("Quartermaster returned a different plan")
    }
    const selected = result.selected
    if (
      !record(selected) ||
      typeof selected.providerID !== "string" ||
      typeof selected.modelID !== "string" ||
      (selected.variant !== undefined &&
        (typeof selected.variant !== "string" || !selected.variant))
    ) {
      throw new Error("Invalid Quartermaster selected model")
    }
    if (
      !route.models.some((id) => {
        const allowed = splitModel(id)
        return allowed.providerID === selected.providerID && allowed.modelID === selected.modelID
      })
    ) {
      throw new Error("Quartermaster model is outside the trusted plan allowlist")
    }
    return {
      providerID: selected.providerID,
      modelID: selected.modelID,
      ...(typeof selected.variant === "string" ? { variant: selected.variant } : {}),
    }
  } finally {
    clearTimeout(timer)
    signal.removeEventListener("abort", abort)
  }
}
