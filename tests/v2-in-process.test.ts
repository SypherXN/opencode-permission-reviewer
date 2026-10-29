import { afterEach, expect, mock, test } from "bun:test"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { pathToFileURL } from "node:url"
import { OpenCode, type OpenCodeClient, type OpenCodeEvent } from "@opencode/client"
import type { Plugin } from "@opencode/plugin"
import { setGlobalConfigPathForTests } from "../src/config/loader.ts"
import {
  createInProcessReviewClient,
  forgetIsolationContext,
  noteIsolationContext,
} from "../src/opencode/v2/in-process-client.ts"
import { connectReviewHost, setup } from "../src/opencode/v2/server.ts"
import { decision } from "./helpers.ts"

type Context = Parameters<Plugin.Plugin["setup"]>[0]
type Input = {
  action: string
  resources: string[]
  metadata: Record<string, unknown>
  sessionID: string
  effect: string
  message?: string
}
type Tool = {
  input: { parse(value: unknown): unknown }
  execute(value: unknown, event: { sessionID: string }): Promise<unknown>
}

const hostUrl = "OPENCODE_PERMISSION_REVIEWER_HOST_URL"
const password = "OPENCODE_PASSWORD"
const legacyPassword = "OPENCODE_SERVER_PASSWORD"
const originalEnv = {
  [hostUrl]: process.env[hostUrl],
  [password]: process.env[password],
  [legacyPassword]: process.env[legacyPassword],
}

afterEach(() => {
  for (const [name, value] of Object.entries(originalEnv)) {
    if (value === undefined) delete process.env[name]
    else process.env[name] = value
  }
  setGlobalConfigPathForTests(undefined)
})

function stubMake(impl: () => OpenCodeClient) {
  const descriptor = Object.getOwnPropertyDescriptor(OpenCode, "make")!
  const make = mock(impl)
  Object.defineProperty(OpenCode, "make", {
    value: make,
    enumerable: descriptor.enumerable ?? false,
    configurable: true,
    writable: true,
  })
  return {
    make,
    restore: () => {
      Object.defineProperty(OpenCode, "make", descriptor)
    },
  }
}

function fakeClient(actualIdentity: string): OpenCodeClient {
  return {
    rpc: () => ({ identity: async () => actualIdentity }),
  } as unknown as OpenCodeClient
}

test("in-process calls target the isolation directory and its own plugin context", async () => {
  const directory = "/tmp/opencode-reviewer-unit"
  const seen: unknown[] = []
  const signal = AbortSignal.timeout(1000)
  const host = {
    mcp: {
      list: async (
        input: { location: { directory: string } },
        options?: { signal?: AbortSignal },
      ) => {
        seen.push(["mcp", input.location.directory, options?.signal])
        return { location: input.location, data: [{ name: "context7" }] }
      },
    },
    plugin: {
      list: async () => {
        throw new Error("host plugin.list")
      },
    },
    model: {
      list: async () => {
        throw new Error("host model.list")
      },
    },
    session: {
      create: async (
        input: { id: string; location: { directory: string } },
        options?: { signal?: AbortSignal },
      ) => {
        seen.push(["create", input.id, input.location.directory, options?.signal])
        return { id: input.id, location: input.location }
      },
      prompt: async () => {
        throw new Error("host session.prompt")
      },
      wait: async () => {
        throw new Error("host session.wait")
      },
      interrupt: async () => {
        throw new Error("host session.interrupt")
      },
      remove: async () => {
        throw new Error("host session.remove")
      },
      get: async () => {
        throw new Error("host session.get")
      },
      context: async () => {
        throw new Error("host session.context")
      },
    },
  }
  const client = createInProcessReviewClient(host as unknown as Context)
  try {
    delete process.env[hostUrl]
    expect((await client.plugin.list({ location: { directory } }, { signal })).data).toEqual([])
    await expect(client.model.list({ location: { directory } }, { signal })).rejects.toThrow(
      "not active",
    )
    const inventory = (await client.mcp.list({ location: { directory } }, { signal })) as {
      location: { directory: string }
      data: Array<{ name: string }>
    }
    expect(inventory).toEqual({
      location: { directory },
      data: [{ name: "context7" }],
    })
    forgetIsolationContext(directory)
    noteIsolationContext(directory, {
      location: { directory: "/workspace" },
      plugin: {
        list: async () => ({ location: { directory: "/workspace" }, data: [] }),
      },
      model: {
        list: async () => ({ location: { directory }, data: [] }),
      },
    })
    await expect(client.plugin.list({ location: { directory } })).rejects.toThrow(
      "plugin inventory belongs to another location",
    )
    forgetIsolationContext(directory)
    noteIsolationContext(directory, {
      location: { directory },
      plugin: {
        list: async () => ({
          location: { directory },
          data: [{ id: "quartermaster", state: { status: "active" } }],
        }),
      },
      model: {
        list: async () => ({
          location: { directory },
          data: [{ providerID: "fixture", id: "reviewer" }],
        }),
      },
      session: {
        prompt: async (input: { sessionID: string; location?: unknown }) => {
          seen.push(["prompt", input.sessionID, input.location])
          return { id: "inbox" }
        },
        wait: async (input: { sessionID: string }) => {
          seen.push(["wait", input.sessionID])
        },
        interrupt: async (input: { sessionID: string }) => {
          seen.push(["interrupt", input.sessionID])
        },
        remove: async (input: { sessionID: string }) => {
          seen.push(["remove", input.sessionID])
        },
        get: async (input: { sessionID: string }) => ({ id: input.sessionID }),
        context: async (input: { sessionID: string }) => {
          seen.push(["context", input.sessionID])
          return []
        },
      },
    })
    const plugins = (await client.plugin.list({ location: { directory } })).data as Array<{
      id: string
      state: { status: string }
    }>
    const models = (await client.model.list({ location: { directory } })).data as Array<{
      providerID: string
      id: string
    }>
    expect(plugins).toEqual([{ id: "quartermaster", state: { status: "active" } }])
    expect(models).toEqual([{ providerID: "fixture", id: "reviewer" }])
    await client.session.create(
      { id: "ses_review", title: "Permission review", location: { directory } },
      { signal },
    )
    await client.session.prompt({ sessionID: "ses_review", text: "review" }, { signal })
    await client.session.wait({ sessionID: "ses_review" }, { signal })
    await client.session.context({ sessionID: "ses_review" }, { signal })
    await client.session.interrupt({ sessionID: "ses_review" }, { signal })
    await client.session.remove({ sessionID: "ses_review" }, { signal })
    expect(seen).toEqual([
      ["mcp", directory, signal],
      ["mcp", directory, signal],
      ["create", "ses_review", directory, signal],
      ["prompt", "ses_review", undefined],
      ["wait", "ses_review"],
      ["context", "ses_review"],
      ["interrupt", "ses_review"],
      ["remove", "ses_review"],
    ])
  } finally {
    forgetIsolationContext(directory)
  }
})

test("a created isolation session is prompted and deleted on that location", async () => {
  const directory = "/tmp/opencode-reviewer-isolation"
  const seen: string[] = []
  const host = {
    mcp: { list: async () => ({ data: [] }) },
    session: {
      create: async (input: { id: string; location: { directory: string } }) => {
        seen.push("host.create")
        return { id: input.id, location: input.location }
      },
      prompt: async () => {
        seen.push("host.prompt")
      },
      get: async () => {
        seen.push("host.get")
        return { id: "ses_user", location: { directory: "/workspace" } }
      },
      remove: async () => {
        seen.push("host.remove")
      },
    },
  }
  noteIsolationContext(directory, {
    location: { directory },
    plugin: { list: async () => ({ location: { directory }, data: [] }) },
    model: { list: async () => ({ location: { directory }, data: [] }) },
    session: {
      prompt: async () => {
        seen.push("isolation.prompt")
      },
      get: async () => {
        throw { _tag: "SessionNotFoundError" }
      },
      remove: async () => {
        seen.push("isolation.remove")
      },
    },
  })
  const client = createInProcessReviewClient(host as unknown as Context)
  try {
    await client.session.create({
      id: "ses_review",
      title: "Permission review",
      location: { directory },
    })
    await client.session.prompt({ sessionID: "ses_review", text: "review" })
    await client.session.get({ sessionID: "ses_user" })
    await expect(client.session.get({ sessionID: "ses_review" })).rejects.toMatchObject({
      _tag: "SessionNotFoundError",
    })
    await client.session.remove({ sessionID: "ses_review" })
    expect(seen).toEqual(["host.create", "isolation.prompt", "host.get", "isolation.remove"])
  } finally {
    forgetIsolationContext(directory)
  }
})

test("a missing isolation context does not ask the host about an owned session", async () => {
  const directory = "/tmp/opencode-reviewer-isolation-gone"
  const seen: string[] = []
  const host = {
    mcp: { list: async () => ({ data: [] }) },
    session: {
      create: async (input: { id: string; location: { directory: string } }) => {
        seen.push("host.create")
        return { id: input.id, location: input.location }
      },
      prompt: async () => {
        seen.push("host.prompt")
      },
      get: async () => {
        seen.push("host.get")
        return { id: "ses_user", location: { directory: "/workspace" } }
      },
      remove: async () => {
        seen.push("host.remove")
      },
    },
  }
  noteIsolationContext(directory, {
    location: { directory },
    plugin: { list: async () => ({ location: { directory }, data: [] }) },
    model: { list: async () => ({ location: { directory }, data: [] }) },
    session: {
      prompt: async () => {
        seen.push("isolation.prompt")
      },
    },
  })
  const client = createInProcessReviewClient(host as unknown as Context)
  try {
    await client.session.create({
      id: "ses_review",
      title: "Permission review",
      location: { directory },
    })
    await expect(client.session.remove({ sessionID: "ses_review" })).rejects.toThrow(
      "isolation session is not reachable",
    )
    forgetIsolationContext(directory)
    await expect(
      client.session.prompt({ sessionID: "ses_review", text: "review" }),
    ).rejects.toThrow("isolation session is not reachable")
    await expect(client.session.remove({ sessionID: "ses_review" })).rejects.toThrow(
      "isolation session is not reachable",
    )
    await client.session.get({ sessionID: "ses_user" })
    expect(seen).toEqual(["host.create", "host.get"])
  } finally {
    forgetIsolationContext(directory)
  }
})

test("explicit host URL keeps the HTTP identity check and in-process does not open one", async () => {
  const ctx = {
    mcp: {
      list: async () => {
        throw new Error("in-process mcp.list")
      },
    },
    session: {},
  } as unknown as Context
  process.env[hostUrl] = "http://127.0.0.1:4096/"
  process.env[password] = "secret"
  delete process.env[legacyPassword]
  const mismatch = stubMake(() => fakeClient("other-generation"))
  try {
    await expect(
      connectReviewHost(ctx, "/workspace", "expected", "2.0.3", AbortSignal.timeout(1000)),
    ).rejects.toThrow("does not belong to this host generation")
    expect(mismatch.make).toHaveBeenCalled()
  } finally {
    mismatch.restore()
  }
  delete process.env[password]
  const unauthenticated = stubMake(() => fakeClient("expected"))
  try {
    await expect(
      connectReviewHost(ctx, "/workspace", "expected", "2.0.3", AbortSignal.timeout(1000)),
    ).rejects.toThrow("requires OPENCODE_PASSWORD")
    expect(unauthenticated.make).not.toHaveBeenCalled()
  } finally {
    unauthenticated.restore()
  }
  delete process.env[hostUrl]
  const stopped = { aborted: true, reason: new Error("stopped") } as AbortSignal
  await expect(connectReviewHost(ctx, "/workspace", "expected", "2.0.3", stopped)).rejects.toThrow(
    "stopped",
  )
  const local = stubMake(() => {
    throw new Error("HTTP client must not be created")
  })
  try {
    const client = await connectReviewHost(
      ctx,
      "/workspace",
      "expected",
      "2.0.3",
      AbortSignal.timeout(1000),
    )
    expect(local.make).not.toHaveBeenCalled()
    expect(client.session).toBeDefined()
  } finally {
    local.restore()
  }
})

async function hostFixture(options: { mcpServers?: boolean; quartermaster?: boolean } = {}) {
  const workspace = await mkdtemp(join(tmpdir(), "reviewer-in-process-"))
  const isolationBase = await mkdtemp(join(tmpdir(), "reviewer-isolation-"))
  const previousIsolationBase = process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
  process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = isolationBase
  const globalPath = join(workspace, "global.jsonc")
  await writeFile(
    globalPath,
    JSON.stringify({
      audit: false,
      model: "fixture/reviewer",
      variant: "max",
      askDecisions: false,
      escalationMode: "deny",
    }),
  )
  setGlobalConfigPathForTests(globalPath)
  let evaluate!: (input: Input) => Promise<void>
  let status!: () => Promise<Record<string, unknown>>
  let resume: (() => void) | undefined
  let ended = false
  const events: OpenCodeEvent[] = []
  const mcpDirectories: string[] = []
  const created: string[] = []
  const promptArguments: Array<Record<string, unknown>> = []
  const removed = new Set<string>()
  let reviewerID = ""
  let tool: Tool | undefined
  let contextHook:
    | ((event: {
        sessionID: string
        system: unknown[]
        messages: unknown[]
        tools: Record<string, unknown>
      }) => void)
    | undefined
  let toolHook: ((event: { sessionID: string; tool: string }) => void) | undefined
  let hostPluginLists = 0
  let hostModelLists = 0
  const registration = () => ({ dispose: async () => {} })
  const isolationContext = (directory: string, pluginID: string) => ({
    location: { directory },
    mcp: {
      transform: async (
        callback: (editor: { list(): [string, unknown][]; remove(name: string): void }) => void,
      ) => {
        const servers = new Map<string, unknown>()
        callback({
          list: () => [...servers],
          remove: (name) => void servers.delete(name),
        })
        return registration()
      },
    },
    tool: {
      transform: async (callback: (editor: { add(definition: Tool): void }) => void) => {
        callback({
          add: (definition) => {
            tool = definition
          },
        })
        return registration()
      },
      hook: async (_name: string, callback: typeof toolHook) => {
        toolHook = callback
        return registration()
      },
    },
    session: {
      hook: async (_name: string, callback: typeof contextHook) => {
        contextHook = callback
        return registration()
      },
      get: async ({ sessionID }: { sessionID: string }) => {
        if (removed.has(sessionID)) throw { _tag: "SessionNotFoundError" }
        return { id: sessionID, location: { directory }, time: { created: 1 } }
      },
      context: async ({ sessionID }: { sessionID: string }) => [
        { type: "user", id: "inbox_fixture", text: "evidence", time: { created: 2 }, sessionID },
        {
          type: "assistant",
          id: "message_result",
          time: { created: 3 },
          content: [
            {
              type: "tool",
              id: "call_result",
              name: "permission_reviewer_result",
              state: { status: "completed" },
            },
          ],
        },
      ],
      prompt: async (input: { sessionID: string; location?: unknown }) => {
        promptArguments.push(input)
        if (!contextHook || !toolHook || !tool) throw new Error("isolation hooks did not register")
        const event = {
          sessionID: input.sessionID,
          system: ["UNTRUSTED_SYSTEM"],
          messages: ["UNTRUSTED_HISTORY"],
          tools: { permission_reviewer_result: tool, read: {}, shell: {} },
        }
        contextHook(event)
        expect(() => toolHook?.({ sessionID: input.sessionID, tool: "shell" })).toThrow(
          "Operational tools",
        )
        await tool.execute(tool.input.parse(decision("allow")), { sessionID: input.sessionID })
        return { id: "inbox_fixture" }
      },
      wait: async () => {},
      interrupt: async () => {},
      remove: async ({ sessionID }: { sessionID: string }) => {
        removed.add(sessionID)
      },
    },
    plugin: {
      list: async () => ({
        location: { directory },
        data: [
          ...(options.quartermaster
            ? [
                {
                  id: "quartermaster",
                  source: { type: "local", path: directory },
                  state: { status: "active" },
                },
              ]
            : []),
          {
            id: pluginID,
            source: { type: "local", path: join(directory, "index.js") },
            state: { status: "active" },
          },
        ],
      }),
    },
    model: {
      list: async () => ({
        location: { directory },
        data: [
          {
            providerID: "fixture",
            id: "reviewer",
            capabilities: { tools: true },
            variants: [{ id: "max" }],
          },
        ],
      }),
    },
  })
  const ctx = {
    app: { version: "2.1.4" },
    options: {},
    location: { directory: workspace, project: { directory: workspace } },
    rpc: {
      register: async (
        _definition: unknown,
        handlers: { status(): Promise<Record<string, unknown>> },
      ) => {
        status = () => handlers.status()
        return { events: { emit: async () => {} }, ...registration() }
      },
    },
    tool: { hook: async () => registration() },
    permission: {
      hook: async (_name: string, callback: typeof evaluate) => {
        evaluate = callback
        return registration()
      },
    },
    plugin: {
      list: async () => {
        hostPluginLists++
        throw new Error("host plugin.list")
      },
    },
    model: {
      list: async () => {
        hostModelLists++
        throw new Error("host model.list")
      },
    },
    mcp: {
      list: async (input: { location: { directory: string } }) => {
        const directory = input.location.directory
        mcpDirectories.push(directory)
        if (directory !== workspace) {
          const plugin = await import(pathToFileURL(join(directory, "index.js")).href)
          const pluginID = plugin.default.id as string
          if (!created.includes(directory)) {
            created.push(directory)
            await plugin.default.setup(isolationContext(directory, pluginID))
          }
        }
        return {
          location: input.location,
          data: options.mcpServers ? [{ name: "fixture" }] : [],
        }
      },
    },
    session: {
      get: async ({ sessionID }: { sessionID: string }) => {
        if (sessionID === reviewerID) throw new Error("host session.get")
        return {
          id: sessionID,
          location: { directory: workspace },
          time: { created: 1 },
        }
      },
      context: async ({ sessionID }: { sessionID: string }) => {
        if (sessionID === reviewerID) throw new Error("host session.context")
        return [{ type: "user", id: "msg_user", text: "Run printf safe", time: { created: 2 } }]
      },
      create: async (input: { id: string; location: { directory: string }; agent?: string }) => {
        reviewerID = input.id
        return { id: input.id, location: input.location, agent: input.agent }
      },
      prompt: async () => {
        throw new Error("host session.prompt")
      },
      wait: async () => {
        throw new Error("host session.wait")
      },
      interrupt: async () => {
        throw new Error("host session.interrupt")
      },
      remove: async () => {
        throw new Error("host session.remove")
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
  } as unknown as Context
  const dispose = await setup(ctx)
  const input = (): Input => ({
    action: "shell",
    resources: ["printf *"],
    metadata: { command: "printf safe" },
    sessionID: "ses_main",
    effect: "ask",
  })
  return {
    evaluate: (value: Input) => evaluate(value),
    input,
    status: () => status(),
    workspace,
    mcpDirectories: () => mcpDirectories,
    isolationDirectories: () => created,
    promptArguments: () => promptArguments,
    hostPluginLists: () => hostPluginLists,
    hostModelLists: () => hostModelLists,
    dispose,
    cleanup: async () => {
      ended = true
      resume?.()
      await dispose()
      await rm(workspace, { recursive: true, force: true })
      for (const directory of created)
        if (directory !== workspace) await rm(directory, { recursive: true, force: true })
      await rm(isolationBase, { recursive: true, force: true })
      await rm(`${isolationBase}.owner`, { force: true })
      if (previousIsolationBase === undefined)
        delete process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
      else process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = previousIsolationBase
    },
  }
}

test("setup reviews through the plugin context without an HTTP login", async () => {
  delete process.env[hostUrl]
  delete process.env[password]
  delete process.env[legacyPassword]
  const http = stubMake(() => {
    throw new Error("HTTP client must not be created")
  })
  const harness = await hostFixture()
  try {
    const input = harness.input()
    await harness.evaluate(input)
    expect(input.effect).toBe("allow")
    expect(input.message).toBeUndefined()
    expect(http.make).not.toHaveBeenCalled()
    expect(harness.hostPluginLists()).toBe(0)
    expect(harness.hostModelLists()).toBe(0)
    expect(await harness.status()).toMatchObject({ connection: "verified", host: "v2" })
    const directory = harness.isolationDirectories()[0]
    if (!directory) throw new Error("isolation directory was not created")
    expect(harness.mcpDirectories().every((listed) => listed === directory)).toBe(true)
    expect(harness.promptArguments()).toEqual([
      expect.objectContaining({
        sessionID: expect.stringMatching(/^ses_/),
        text: expect.any(String),
      }),
    ])
    expect(harness.promptArguments()[0]?.location).toBeUndefined()
    const isolated = JSON.parse(await readFile(join(directory!, "opencode.json"), "utf8")) as {
      plugins: string[]
    }
    expect(isolated.plugins).toEqual([
      "-opencode.config.mcp",
      "-quartermaster",
      "-opencode-usage",
      directory,
    ])
    expect(await readFile(join(directory, "index.js"), "utf8")).toContain("ctx.mcp.transform")
  } finally {
    http.restore()
    await harness.cleanup()
  }
})

test("in-process reviews still fail closed for Quartermaster and MCP servers", async () => {
  delete process.env[hostUrl]
  for (const options of [{ quartermaster: true }, { mcpServers: true }]) {
    const harness = await hostFixture(options)
    try {
      const input = harness.input()
      await harness.evaluate(input)
      expect(input.effect).toBe("deny")
      expect(input.message).toContain(
        options.quartermaster ? "Quartermaster" : "contains MCP servers",
      )
      expect(harness.promptArguments()).toEqual([])
      expect(await harness.status()).toMatchObject({ connection: "verified" })
      expect(harness.hostPluginLists()).toBe(0)
      expect(harness.hostModelLists()).toBe(0)
    } finally {
      await harness.cleanup()
    }
  }
})

test("setup still requires a password for an explicit host URL", async () => {
  process.env[hostUrl] = "http://127.0.0.1:9/"
  delete process.env[password]
  delete process.env[legacyPassword]
  const http = stubMake(() => fakeClient("expected"))
  const harness = await hostFixture()
  try {
    const input = harness.input()
    await harness.evaluate(input)
    expect(input.effect).toBe("deny")
    expect(input.message).toContain("requires OPENCODE_PASSWORD")
    expect(http.make).not.toHaveBeenCalled()
    expect(harness.isolationDirectories()).toEqual([])
    expect(await harness.status()).toMatchObject({ connection: "failed" })
  } finally {
    http.restore()
    await harness.cleanup()
  }
})
