import { expect, test } from "bun:test"
import { resolveConfig } from "../src/config.ts"
import { selectPlanModel } from "../src/opencode/v2/plan-routing.ts"

test("named-plan routing is optional and validates the trusted selection boundary", () => {
  expect(resolveConfig({}).planRouting).toBeUndefined()
  expect(resolveConfig({ planRouting: { enabled: false } }).planRoutingRejected).toBeUndefined()
  for (const planRouting of [
    null,
    {},
    { enabled: true, plan: "review", models: [] },
    { enabled: true, plan: "", models: ["fixture/model"] },
    { enabled: true, plan: "review", models: ["opencode/jev-1.13-free"] },
  ]) {
    expect(resolveConfig({ planRouting }).planRoutingRejected).toBe(true)
  }
  expect(
    resolveConfig({ planRouting: { enabled: true, plan: "review", models: ["fixture/model"] } })
      .planRouting,
  ).toEqual({ plan: "review", models: ["fixture/model"] })
})

test("plan selection bounds an unresponsive RPC and honours cancellation", async () => {
  let signal: AbortSignal | undefined
  let calls = 0
  const ctx = {
    rpc: () => ({
      selectPlan: (_input: unknown, options: { signal: AbortSignal }) => {
        calls++
        signal = options.signal
        return new Promise(() => {})
      },
    }),
  } as unknown as Parameters<typeof selectPlanModel>[0]
  const config = resolveConfig({
    planRouting: { enabled: true, plan: "review", models: ["fixture/model"] },
  })
  await expect(selectPlanModel(ctx, config, new AbortController().signal, 10)).rejects.toThrow(
    "timed out",
  )
  expect(signal?.aborted).toBe(true)
  const controller = new AbortController()
  const pending = selectPlanModel(ctx, config, controller.signal)
  controller.abort()
  await expect(pending).rejects.toThrow("cancelled")
  expect(signal?.aborted).toBe(true)
  await expect(selectPlanModel(ctx, config, controller.signal)).rejects.toThrow()
  expect(calls).toBe(2)
})
