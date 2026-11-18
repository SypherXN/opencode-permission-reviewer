import { expect, test } from "bun:test"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { resolveReviewTheme, setupTuiV2, testRender } from "./tui-loader.ts"
import { createUiStatus } from "../src/ui-protocol.ts"
import { sessionDisabled, SESSION_TOGGLE_PATH_ENV } from "../src/session-toggle.ts"
import { request } from "./helpers.ts"

test("TUI resolves nested, flat, and unavailable host themes", () => {
  expect(
    resolveReviewTheme({
      background: { surface: { overlay: "nested-background" } },
      text: {
        default: "nested-text",
        subdued: "nested-muted",
        status: { running: "nested-info" },
        feedback: {
          success: { default: "nested-success" },
          error: { default: "nested-error" },
        },
      },
    }),
  ).toEqual({
    backgroundPanel: "nested-background",
    text: "nested-text",
    textMuted: "nested-muted",
    info: "nested-info",
    success: "nested-success",
    error: "nested-error",
  })
  expect(
    resolveReviewTheme({
      background: { raised: { base: "current-background" } },
      text: {
        base: "current-text",
        muted: "current-muted",
        feedback: {
          info: { base: "current-info" },
          success: { base: "current-success" },
          error: { base: "current-error" },
        },
      },
    }),
  ).toEqual({
    backgroundPanel: "current-background",
    text: "current-text",
    textMuted: "current-muted",
    info: "current-info",
    success: "current-success",
    error: "current-error",
  })
  expect(
    resolveReviewTheme({
      backgroundPanel: "flat-background",
      text: "flat-text",
      textMuted: "flat-muted",
      info: "flat-info",
      success: "flat-success",
      error: "flat-error",
    }),
  ).toEqual({
    backgroundPanel: "flat-background",
    text: "flat-text",
    textMuted: "flat-muted",
    info: "flat-info",
    success: "flat-success",
    error: "flat-error",
  })
  expect(resolveReviewTheme(undefined)).toMatchObject({
    backgroundPanel: expect.any(String),
    text: expect.any(String),
  })
  // Bun's toMatchObject writes the asymmetric matchers into the received
  // object; the fallback must be a fresh copy so that never leaks.
  expect(resolveReviewTheme(undefined)).not.toBe(resolveReviewTheme(undefined))
  expect(resolveReviewTheme(undefined).backgroundPanel).toBe("#111111")
})

test("TUI restores authoritative snapshots after disconnect and isolates routes, revisions, and generations", async () => {
  const directory = "/workspace/fixture"
  let sessionID = "ses_main"
  let modeDepth = 0
  let snapshots = 0
  let releaseSnapshot!: () => void
  const snapshotGate = new Promise<void>((resolve) => {
    releaseSnapshot = resolve
  })
  let render!: () => unknown
  const toasts: unknown[] = []
  const reviewing = {
    ...createUiStatus(request(), "reviewing", {
      model: "fixture/reviewer",
      variant: "max",
      timeoutMs: 10000,
    }),
    action: `printf ${"long action ".repeat(30)}\nsecond line\tend`,
  }
  let snapshot = { directory, generation: "generation_first", revision: 1, reviews: [reviewing] }
  type Channel = { queue: unknown[]; ended: boolean; wake?: () => void }
  const channels: Channel[] = []
  const ctx = {
    location: { directory },
    data: { session: { get: () => ({ location: { directory } }) } },
    keymap: {
      mode: {
        push: () => {
          modeDepth++
          return () => {
            modeDepth--
          }
        },
      },
    },
    ui: {
      router: { current: () => ({ type: "session", sessionID }) },
      toast: { show: (value: unknown) => toasts.push(value) },
      slot: (definition: { render(): unknown }) => {
        render = definition.render
        return () => {}
      },
    },
    client: {
      event: {
        subscribe: () => {
          throw new Error("TUI snapshot loading must not depend on a generic host event")
        },
      },
      rpc: () => ({
        snapshot: async () => {
          snapshots++
          if (snapshots > 1) await snapshotGate
          return snapshot
        },
        events: {
          subscribe: async function* (_name: string, { signal }: { signal: AbortSignal }) {
            const channel: Channel = { queue: [], ended: false }
            channels.push(channel)
            const wake = () => channel.wake?.()
            signal.addEventListener("abort", wake)
            try {
              while (!signal.aborted && !channel.ended) {
                if (channel.queue.length) yield channel.queue.shift()
                else
                  await new Promise<void>((resolve) => {
                    channel.wake = resolve
                  })
              }
            } finally {
              signal.removeEventListener("abort", wake)
            }
          },
        },
      }),
    },
  } as unknown as Parameters<typeof setupTuiV2>[0]
  const dispose = await setupTuiV2(ctx)
  const view = await testRender(() => render() as Element, { width: 100, height: 24 })
  const waitForFrame = async (text: string, present = true) => {
    const deadline = Date.now() + 3000
    do {
      await view.flush()
      if (view.captureCharFrame().includes(text) === present) return
      await Bun.sleep(10)
    } while (Date.now() < deadline)
    expect(view.captureCharFrame().includes(text), view.captureCharFrame()).toBe(present)
  }
  try {
    await waitForFrame("Reviewing this permission")
    const progressFrame = view.captureCharFrame()
    const occupied = progressFrame.split("\n").filter((line) => line.trim())
    expect(occupied).toHaveLength(2)
    expect(progressFrame.split("\n").findIndex((line) => line.trim())).toBe(22)
    expect(occupied[0]).toContain("fixture/reviewer")
    expect(occupied[1]).toContain("printf long action")
    const firstElapsed = Number(progressFrame.match(/(\d+\.\d)s/)?.[1])
    await Bun.sleep(700)
    await view.flush()
    expect(Number(view.captureCharFrame().match(/(\d+\.\d)s/)?.[1])).toBeGreaterThan(firstElapsed)
    expect(modeDepth).toBe(1)
    sessionID = "ses_other"
    await waitForFrame("Reviewing this permission", false)
    expect(modeDepth).toBe(0)
    sessionID = "ses_main"
    await waitForFrame("Reviewing this permission")
    expect(modeDepth).toBe(1)

    snapshot = {
      directory,
      generation: "generation_second",
      revision: 2,
      reviews: [
        createUiStatus(request(), "denied", {
          model: "fixture/reviewer",
          variant: "max",
          timeoutMs: 10000,
          reason: "Authoritative denial",
        }),
      ],
    }
    channels[0]!.ended = true
    channels[0]!.wake?.()
    await waitForFrame("Review status unavailable")
    expect(view.captureCharFrame()).not.toContain("Review approved")
    expect(modeDepth).toBe(0)
    releaseSnapshot()
    await waitForFrame("Review blocked")
    expect(snapshots).toBe(2)
    expect(view.captureCharFrame()).toContain("Review blocked")
    const channel = channels.at(-1)!
    channel.queue.push(
      {
        location: { directory },
        data: {
          directory,
          revision: 999,
          status: createUiStatus(request(), "approved", {
            model: "fixture/reviewer",
            variant: "max",
            timeoutMs: 10000,
          }),
        },
      },
      {
        location: { directory },
        data: {
          directory,
          generation: "generation_second",
          revision: 1,
          status: createUiStatus(request(), "approved", {
            model: "fixture/reviewer",
            variant: "max",
            timeoutMs: 10000,
          }),
        },
      },
      {
        location: { directory: "/other" },
        data: {
          directory: "/other",
          generation: "generation_second",
          revision: 3,
          status: createUiStatus(request(), "manual", {
            model: "fixture/reviewer",
            variant: "max",
            timeoutMs: 10000,
          }),
        },
      },
    )
    channel.wake?.()
    await Bun.sleep(10)
    await view.flush()
    expect(view.captureCharFrame()).toContain("Review blocked")
    expect(view.captureCharFrame()).not.toContain("Review approved")
    expect(toasts).toHaveLength(0)
  } finally {
    releaseSnapshot()
    dispose()
    view.renderer.destroy()
  }
  expect(modeDepth).toBe(0)
}, 10000)

test("/opr command switches the session it is invoked from and never throws", async () => {
  const directory = "/workspace/fixture"
  const dir = mkdtempSync(join(tmpdir(), "reviewer-tui-opr-"))
  const path = join(dir, "sessions.json")
  const previous = process.env[SESSION_TOGGLE_PATH_ENV]
  process.env[SESSION_TOGGLE_PATH_ENV] = path
  type Toast = { variant?: string; title?: string; message: string }
  const toasts: Toast[] = []
  let sessionID: string | undefined = "ses_main"
  type Command = {
    slash?: { name: string; arguments?: boolean }
    run(input?: string): Promise<void> | void
  }
  let command: Command | undefined
  const ctx = {
    location: { directory },
    data: { session: { get: () => ({ location: { directory } }) } },
    keymap: {
      mode: { push: () => () => {} },
      layer: (factory: () => unknown) => {
        command = (factory() as { commands: Command[] }).commands[0]
      },
    },
    ui: {
      router: {
        current: () =>
          sessionID === undefined ? { type: "home" } : { type: "session", sessionID },
      },
      toast: { show: (value: Toast) => toasts.push(value) },
      slot: () => () => {},
    },
    client: {
      rpc: () => ({
        snapshot: async () => ({ directory, generation: "generation", revision: 0, reviews: [] }),
        events: {
          subscribe: async function* () {},
        },
      }),
    },
  } as unknown as Parameters<typeof setupTuiV2>[0]
  const dispose = await setupTuiV2(ctx)
  try {
    expect(command?.slash).toMatchObject({ name: "opr", arguments: true })
    const run = (input: string) => command!.run(input)
    const last = () => toasts.at(-1)!

    await run("/opr status")
    expect(last().title).toBe("OPR is on for this session")

    await run("/opr off")
    expect(last().title).toBe("OPR off for this session")
    expect(sessionDisabled("ses_main")).toEqual({ disabled: true, reason: "tui" })

    await run("/opr status")
    expect(last().title).toBe("OPR is off for this session")
    expect(last().message).toContain("reason: tui")

    await run("/opr off --minutes 30")
    const until = sessionDisabled("ses_main").until
    expect(typeof until).toBe("string")
    expect(Date.parse(until!)).toBeGreaterThan(Date.now())

    await run("/opr on")
    expect(last().title).toBe("OPR on for this session")
    expect(sessionDisabled("ses_main")).toEqual({ disabled: false })

    await run("/opr on")
    expect(last().title).toBe("OPR was already on for this session")

    await run("/opr off --minutes zero")
    expect(last().title).toBe("Invalid --minutes")
    expect(sessionDisabled("ses_main")).toEqual({ disabled: false })

    sessionID = undefined
    await run("/opr off")
    expect(last().title).toBe("No active session")
    expect(sessionDisabled("ses_main")).toEqual({ disabled: false })

    // A write failure is reported, not thrown out of the command.
    sessionID = "ses_main"
    writeFileSync(join(dir, "blocker"), "not a directory")
    process.env[SESSION_TOGGLE_PATH_ENV] = join(dir, "blocker", "sessions.json")
    await run("/opr off")
    expect(last()).toMatchObject({ variant: "error", title: "OPR command failed" })
  } finally {
    dispose()
    if (previous === undefined) delete process.env[SESSION_TOGGLE_PATH_ENV]
    else process.env[SESSION_TOGGLE_PATH_ENV] = previous
    rmSync(dir, { recursive: true, force: true })
  }
}, 10000)

test("TUI keeps the overlay on a host without keymap layers", async () => {
  const directory = "/workspace/fixture"
  const ctx = {
    location: { directory },
    data: { session: { get: () => ({ location: { directory } }) } },
    keymap: { mode: { push: () => () => {} } },
    ui: {
      router: { current: () => ({ type: "home" }) },
      toast: {
        show: () => {
          throw new Error("this host has no toasts either")
        },
      },
      slot: () => () => {},
    },
    client: {
      rpc: () => ({
        snapshot: async () => ({ directory, generation: "generation", revision: 0, reviews: [] }),
        events: {
          subscribe: async function* () {},
        },
      }),
    },
  } as unknown as Parameters<typeof setupTuiV2>[0]
  const dispose = await setupTuiV2(ctx)
  dispose()
}, 10000)
