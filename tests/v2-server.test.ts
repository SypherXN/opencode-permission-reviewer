import { expect, test } from "bun:test"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { tmpdir } from "node:os"
import type { OpenCodeClient, OpenCodeEvent } from "@opencode/client"
import { setupWithServices } from "../src/opencode/v2/server.ts"
import { normalizeV2Permission } from "../src/opencode/v2/permission-codec.ts"
import { SESSION_TOGGLE_PATH_ENV } from "../src/session-toggle.ts"
import type { ReviewExecutionResult } from "../src/types.ts"
import { config, decision } from "./helpers.ts"

type Input = Parameters<typeof normalizeV2Permission>[0] & { message?: string }

async function fixture(
  options: {
    result?: ReviewExecutionResult
    delay?: Promise<void>
    connectionError?: boolean
    budget?: number
    hostVersion?: string
    auxiliarySessionID?: string
    beforeSessionGet?: (sessionID: string) => Promise<void>
  } = {},
) {
  const directory = await mkdtemp(join(tmpdir(), "reviewer-server-contract-"))
  const auditPath = join(directory, "audit.jsonl")
  const togglePath = join(directory, "sessions.json")
  let evaluate!: (input: Input) => Promise<void>
  let rpc!: {
    identity(): Promise<string>
    status(): Promise<Record<string, unknown>>
    snapshot(): Promise<{ reviews: unknown[] }>
  }
  let resume: (() => void) | undefined
  const events: OpenCodeEvent[] = []
  let ended = false
  let reviews = 0
  let registrationDisposals = 0
  const toolHooks = new Map<string, (event: unknown) => void>()
  const commands = new Map<string, (input: { sessionID: string }) => Promise<void>>()
  const lookups: string[] = []
  const sessions = new Map<
    string,
    { id?: string; parentID?: unknown; location?: { directory: string } } | null
  >()
  const sessionInfo = (sessionID: string) => {
    const overrides = sessions.get(sessionID)
    return overrides === null
      ? null
      : { id: sessionID, location: { directory }, time: { created: 1 }, ...overrides }
  }
  const registration = () => ({
    dispose: async () => {
      registrationDisposals++
    },
  })
  const ctx = {
    app: { version: options.hostVersion ?? "2.0.3" },
    options: {},
    location: { directory, project: { directory } },
    rpc: {
      register: async (_definition: unknown, handlers: typeof rpc) => {
        rpc = handlers
        return { events: { emit: async () => {} }, ...registration() }
      },
    },
    tool: {
      hook: async (name: string, callback: (event: unknown) => void) => {
        toolHooks.set(name, callback)
        return registration()
      },
    },
    command: {
      transform: async (callback: (editor: unknown) => void) => {
        callback({
          add: (definition: { name: string; execute: (input: { sessionID: string }) => Promise<void> }) => {
            commands.set(definition.name, definition.execute)
          },
        })
        return registration()
      },
    },
    permission: {
      hook: async (_name: string, callback: typeof evaluate) => {
        evaluate = callback
        return registration()
      },
    },
    session: {
      get: async ({ sessionID }: { sessionID: string }) => {
        lookups.push(sessionID)
        if (options.beforeSessionGet) await options.beforeSessionGet(sessionID)
        return sessionInfo(sessionID)
      },
    },
    event: {
      subscribe: async function* ({ signal }: { signal: AbortSignal }) {
        const wake = () => resume?.()
        signal.addEventListener("abort", wake)
        try {
          while (!signal.aborted && !ended) {
            if (events.length) yield events.shift()!
            else
              await new Promise<void>((resolve) => {
                resume = resolve
              })
          }
        } finally {
          signal.removeEventListener("abort", wake)
        }
      },
    },
  } as unknown as Parameters<typeof setupWithServices>[0]
  const client = {
    session: {
      get: async ({ sessionID }: { sessionID: string }) => sessionInfo(sessionID),
      context: async () => [
        { type: "user", id: "msg_user", text: "Run printf safe", time: { created: 2 } },
      ],
    },
  } as unknown as OpenCodeClient
  const dispose = await setupWithServices(ctx, {
    loadConfig: () => config({ audit: true, auditPath, reviewBudgetMs: options.budget ?? 5000 }),
    connect: async () => {
      if (options.connectionError) throw new Error("Connection identity mismatch")
      return client
    },
    createBackend: () => ({
      owns: (sessionID) => sessionID === options.auxiliarySessionID,
      waitForIdle: async () => {},
      dispose: async () => {},
      review: async () => {
        reviews++
        await options.delay
        return (
          options.result ?? {
            kind: "allow",
            reason: "Fixture decision",
            decision: decision("allow"),
            decisionSource: "llm-reviewer",
          }
        )
      },
    }),
  })
  const input = (sessionID = "ses_main"): Input => ({
    action: "shell",
    resources: ["printf *"],
    metadata: { command: "printf safe" },
    sessionID,
    effect: "ask",
  })
  const previousTogglePath = process.env[SESSION_TOGGLE_PATH_ENV]
  process.env[SESSION_TOGGLE_PATH_ENV] = togglePath
  return {
    evaluate: (value: Input) => evaluate(value),
    input,
    rpc,
    directory,
    togglePath,
    lookups,
    sessions,
    reviews: () => reviews,
    registrationDisposals: () => registrationDisposals,
    endEvents: () => {
      ended = true
      resume?.()
    },
    event: (sessionID: string, location = directory) => {
      events.push({
        type: "session.execution.interrupted",
        data: { sessionID },
        location: { directory: location },
      } as OpenCodeEvent)
      resume?.()
    },
    tool: (name: string, event: unknown) => toolHooks.get(name)?.(event),
    commandNames: () => [...commands.keys()].sort(),
    command: (name: string, sessionID: string) => commands.get(name)!({ sessionID }),
    dispose,
    records: async () =>
      (await readFile(auditPath, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as Record<string, unknown>),
    cleanup: async () => {
      try {
        await dispose()
      } finally {
        if (previousTogglePath === undefined) delete process.env[SESSION_TOGGLE_PATH_ENV]
        else process.env[SESSION_TOGGLE_PATH_ENV] = previousTogglePath
      }
      await rm(directory, { recursive: true, force: true })
    },
  }
}

test("server maps decisions without elevating existing allow or deny and reports application independently", async () => {
  for (const kind of ["allow", "deny", "escalate"] as const) {
    const harness = await fixture({
      result: {
        kind,
        reason: "Fixture outcome",
        decision: decision(kind),
        decisionSource: "llm-reviewer",
      },
    })
    try {
      for (const effect of ["allow", "deny"] as const) {
        const unchanged = { ...harness.input(), effect }
        await harness.evaluate(unchanged)
        expect(unchanged.effect).toBe(effect)
      }
      expect(harness.reviews()).toBe(0)
      const input = harness.input()
      await harness.evaluate(input)
      expect(input.effect).toBe(kind === "escalate" ? "ask" : kind)
      expect(harness.reviews()).toBe(1)
      expect((await harness.rpc.snapshot()).reviews).toHaveLength(1)
      expect(await harness.rpc.status()).toMatchObject({
        host: "v2",
        pending: 0,
        connection: "verified",
      })
      expect(await harness.rpc.identity()).toBeTruthy()
      await harness.dispose()
      expect(harness.registrationDisposals()).toBe(5)
      expect((await harness.records())[0]?.application).toBe(
        kind === "escalate" ? "human-pending" : "evaluation-returned",
      )
      const after = harness.input()
      await harness.evaluate(after)
      expect(after.effect).toBe("deny")
    } finally {
      await harness.cleanup()
    }
  }
})

test("a session switched off leaves the request as ask, with no review", async () => {
  const harness = await fixture()
  try {
    await writeFile(
      harness.togglePath,
      JSON.stringify({ version: 1, off: { ses_main: { reason: "pairing" } } }),
    )
    const input = harness.input()
    await harness.evaluate(input)
    // Off never decides anything: OpenCode's own prompt reaches the human.
    expect(input.effect).toBe("ask")
    expect(harness.reviews()).toBe(0)
    await Bun.sleep(20)
    const records = await harness.records()
    expect(records).toHaveLength(1)
    expect(records[0]).toMatchObject({
      decisionSource: "session-disabled",
      application: "human-pending",
      outcome: "escalate",
    })
    expect(String(records[0]?.reason)).toContain("pairing")

    // Another session keeps its normal review.
    const other = harness.input("ses_other")
    await harness.evaluate(other)
    expect(other.effect).toBe("allow")
    expect(harness.reviews()).toBe(1)
  } finally {
    await harness.cleanup()
  }
})

test("slash commands switch a chat and its native descendants, not unrelated chats", async () => {
  const harness = await fixture()
  try {
    harness.sessions.set("ses_child", { parentID: "ses_main" })
    harness.sessions.set("ses_nested", { parentID: "ses_child" })
    expect(harness.commandNames()).toEqual(["opr-off", "opr-on"])
    await harness.command("opr-off", "ses_main")
    const off = harness.input("ses_main")
    await harness.evaluate(off)
    expect(off.effect).toBe("ask")
    expect(harness.lookups).toEqual([])
    for (const sessionID of ["ses_child", "ses_nested"]) {
      const descendant = harness.input(sessionID)
      await harness.evaluate(descendant)
      expect(descendant.effect).toBe("ask")
      expect(descendant.message).toBeUndefined()
    }
    expect(harness.reviews()).toBe(0)
    expect((await harness.rpc.snapshot()).reviews).toEqual([])
    // A claimed parent in permission metadata cannot turn the reviewer off.
    const other = {
      ...harness.input("ses_other"),
      metadata: { command: "printf safe", parentID: "ses_main" },
    }
    await harness.evaluate(other)
    expect(other.effect).toBe("allow")
    expect(harness.reviews()).toBe(1)
    await harness.command("opr-on", "ses_main")
    const lookupsBefore = harness.lookups.length
    const back = harness.input("ses_nested")
    await harness.evaluate(back)
    expect(back.effect).toBe("allow")
    expect(harness.reviews()).toBe(2)
    expect(harness.lookups.slice(lookupsBefore)).toEqual(["ses_nested"])
    await harness.dispose()
    const disabled = (await harness.records()).filter(
      (record) => record.decisionSource === "session-disabled",
    )
    expect(disabled.map((record) => record.sessionID).sort()).toEqual([
      "ses_child",
      "ses_main",
      "ses_nested",
    ])
    for (const record of disabled) {
      expect(record).toMatchObject({ application: "human-pending", outcome: "escalate" })
      expect(record.reason).toBe("OPR is off for this chat: command")
    }
  } finally {
    await harness.cleanup()
  }
})

test("invalid native lineage and auxiliary sessions cannot inherit an off entry", async () => {
  const harness = await fixture({ auxiliarySessionID: "ses_auxiliary" })
  try {
    await harness.command("opr-off", "ses_main")
    for (const parent of [
      null,
      { id: "ses_wrong" },
      { location: { directory: "/another-location" } },
      { parentID: "ses_child" },
      { parentID: "" },
      { parentID: 42 },
    ]) {
      harness.sessions.set("ses_child", { parentID: "ses_main" })
      harness.sessions.set("ses_main", parent)
      const child = harness.input("ses_child")
      await harness.evaluate(child)
      expect(child.effect).toBe("allow")
    }
    harness.sessions.set("ses_main", {})
    harness.sessions.set("ses_child", { id: "ses_wrong", parentID: "ses_main" })
    const wrongChild = harness.input("ses_child")
    await harness.evaluate(wrongChild)
    expect(wrongChild.effect).toBe("allow")

    harness.sessions.set("ses_auxiliary", { parentID: "ses_main" })
    const auxiliary = harness.input("ses_auxiliary")
    await harness.evaluate(auxiliary)
    expect(auxiliary.effect).toBe("deny")
    expect(auxiliary.message).toContain("Automatic reviewer sessions may not request")
    expect(harness.reviews()).toBe(7)
  } finally {
    await harness.cleanup()
  }
})

test("ancestry that exceeds the configured depth cannot inherit even a nearer off entry", async () => {
  const harness = await fixture()
  try {
    const { maxSessionDepth, maxParentSessions } = config()
    const limit = Math.min(maxSessionDepth, maxParentSessions)
    for (let index = 0; index <= limit; index++) {
      harness.sessions.set(`ses_${index}`, { parentID: `ses_${index + 1}` })
    }
    await harness.command("opr-off", "ses_1")
    const child = harness.input("ses_0")
    await harness.evaluate(child)
    expect(child.effect).toBe("allow")
    expect(harness.lookups).toHaveLength(limit + 1)
  } finally {
    await harness.cleanup()
  }
})

test("pending inheritance respects cancellation and a concurrent /opr-on", async () => {
  for (const change of ["interrupt", "event-loss", "shutdown", "deadline", "on"] as const) {
    let start!: () => void
    let release!: () => void
    const started = new Promise<void>((resolve) => {
      start = resolve
    })
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    const harness = await fixture({
      budget: change === "deadline" ? 50 : 5000,
      beforeSessionGet: async (sessionID) => {
        if (sessionID !== "ses_main") return
        start()
        await held
      },
    })
    try {
      harness.sessions.set("ses_child", { parentID: "ses_main" })
      await harness.command("opr-off", "ses_main")
      const child = harness.input("ses_child")
      const work = harness.evaluate(child)
      await Promise.race([started, work])
      expect(await harness.rpc.status()).toMatchObject({ pending: 1 })
      expect((await harness.rpc.snapshot()).reviews).toEqual([])
      if (change === "interrupt") harness.event("ses_child")
      if (change === "event-loss") harness.endEvents()
      if (change === "shutdown") await harness.dispose()
      if (change === "on") {
        await harness.command("opr-on", "ses_main")
        release()
      }
      await work
      release()
      expect(child.effect).toBe(change === "on" ? "allow" : "deny")
      expect(harness.reviews()).toBe(change === "on" ? 1 : 0)
      await harness.dispose()
      expect((await harness.records()).map((record) => record.application)).toEqual([
        change === "on" ? "evaluation-returned" : "cancelled",
      ])
    } finally {
      release()
      await harness.cleanup()
    }
  }
})

test("a session switched off behaves like OpenCode without the plugin", async () => {
  const harness = await fixture()
  try {
    await writeFile(harness.togglePath, JSON.stringify({ version: 1, off: { ses_main: {} } }))
    // Root destruction is OPR's own brake, not a host rule. With OPR off the
    // request stays `ask` like any other: the human decides.
    const input = { ...harness.input(), metadata: { command: "rm -rf /" } }
    await harness.evaluate(input)
    expect(input.effect).toBe("ask")
    expect(harness.reviews()).toBe(0)
  } finally {
    await harness.cleanup()
  }
})

test("deadline, interrupted session, event loss, and shutdown suppress late approvals", async () => {
  for (const interruption of ["deadline", "session", "event-loss", "shutdown"] as const) {
    let release!: () => void
    const delay = new Promise<void>((resolve) => {
      release = resolve
    })
    const harness = await fixture({ delay, budget: interruption === "deadline" ? 20 : 5000 })
    try {
      const input = harness.input()
      const work = harness.evaluate(input)
      while (harness.reviews() === 0) await Bun.sleep(1)
      harness.event("ses_main", "/another-location")
      await Bun.sleep(1)
      expect(input.effect).toBe("ask")
      if (interruption === "session") harness.event("ses_main")
      if (interruption === "event-loss") harness.endEvents()
      if (interruption === "shutdown") await harness.dispose()
      await work
      expect(input.effect).toBe("deny")
      release()
      await Bun.sleep(1)
      expect(input.effect).toBe("deny")
    } finally {
      release()
      await harness.cleanup()
    }
  }
})

test("overload stays bounded and independent sessions keep independent outcomes", async () => {
  let release!: () => void
  const harness = await fixture({
    delay: new Promise<void>((resolve) => {
      release = resolve
    }),
  })
  try {
    const inputs = Array.from({ length: 32 }, (_, index) => harness.input(`ses_${index}`))
    const work = Promise.all(inputs.map(harness.evaluate))
    while (harness.reviews() < 32) await Bun.sleep(1)
    const overload = harness.input("ses_overload")
    await harness.evaluate(overload)
    expect(overload.effect).toBe("deny")
    expect((await harness.rpc.status()).pending).toBe(32)
    harness.event("ses_0")
    release()
    await work
    expect(inputs[0]?.effect).toBe("deny")
    expect(inputs.slice(1).every((input) => input.effect === "allow")).toBe(true)
  } finally {
    release()
    await harness.cleanup()
  }
})

test("v2 host setup enforces the supported range and reports it", async () => {
  for (const version of ["2.0.3", "2.0.4", "2.0.11", "2.0.12", "2.1.0"]) {
    const harness = await fixture({ hostVersion: version })
    try {
      expect(await harness.rpc.status()).toMatchObject({ host: "v2", hostVersion: version })
    } finally {
      await harness.cleanup()
    }
  }
  for (const version of ["2.0.2", "3.0.0", "2.0.3-beta.1"]) {
    const ctx = {
      app: { version },
      location: { directory: "/tmp", project: { directory: "/tmp" } },
    } as unknown as Parameters<typeof setupWithServices>[0]
    const services = {
      loadConfig: () => {
        throw new Error("setup must reject the host before loading config")
      },
      connect: () => {
        throw new Error("setup must reject the host before connecting")
      },
      createBackend: () => {
        throw new Error("setup must reject the host before creating a backend")
      },
    } as unknown as Parameters<typeof setupWithServices>[1]
    await expect(setupWithServices(ctx, services)).rejects.toThrow(
      `Unsupported OpenCode V2 host ${version}; supported range is >=2.0.3 <3`,
    )
  }
})

test("action mutations and incomplete evidence cannot reuse an approval, and connection failures stay visible", async () => {
  let release!: () => void
  const changing = await fixture({
    delay: new Promise<void>((resolve) => {
      release = resolve
    }),
  })
  try {
    const input = changing.input()
    const work = changing.evaluate(input)
    while (changing.reviews() === 0) await Bun.sleep(1)
    Reflect.set(input, "metadata", { command: "printf changed" })
    release()
    await work
    expect(input.effect).toBe("deny")
    expect(input.message).toContain("changed during")
  } finally {
    release()
    await changing.cleanup()
  }
  for (const connectionError of [false, true]) {
    const harness = await fixture({ connectionError })
    try {
      const input = harness.input()
      Reflect.set(input, "metadata", {})
      await harness.evaluate(input)
      expect(input.effect).not.toBe("allow")
      if (connectionError)
        expect(await harness.rpc.status()).toMatchObject({ connection: "failed" })
    } finally {
      await harness.cleanup()
    }
  }
})
