import { expect, test } from "bun:test"
import { existsSync, mkdtempSync } from "node:fs"
import { readFile, copyFile, mkdir, readdir, rm, stat, utimes, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { pathToFileURL } from "node:url"
import type { OpenCodeClient } from "@opencode/client"
import type { Plugin } from "@opencode/plugin"
import { createV2ReviewerBackend } from "../src/opencode/v2/backend-factory.ts"
import {
  forceReviewerCompletion,
  forceReviewerFrame,
} from "../src/opencode/v2/reviewer-backend.ts"
import { createIsolatedLocation } from "../src/opencode/v2/isolated-location.ts"
import { SYSTEM_ONE_QUESTIONS } from "../src/system-one/review.ts"
import { DEFAULT_CONFIG } from "../src/config.ts"
import { ReviewAttempt } from "../src/core/review-attempt.ts"
import type { ReviewEnvelope, ReviewerConfig } from "../src/types.ts"
import { config, decision, request } from "./helpers.ts"

type Context = Parameters<Plugin.Plugin["setup"]>[0]
type McpEditor = Parameters<Parameters<Context["mcp"]["transform"]>[0]>[0]
type McpServer = NonNullable<ReturnType<McpEditor["get"]>>
type Tool = {
  input: { parse(value: unknown): unknown }
  execute(value: unknown, event: { sessionID: string }): Promise<unknown>
}
type ContextEvent = {
  sessionID: string
  system: unknown[]
  messages: unknown[]
  tools: Record<string, unknown>
  options?: { maxTokens?: number }
}

function fixture(
  options: {
    format?: ReviewerConfig["outputFormat"]
    invalid?: boolean
    ambiguous?: boolean
    textBody?: string
    reasoningBody?: string
    lowBudget?: boolean
    toolError?: unknown
    toolErrors?: unknown[]
    streamingStored?: boolean
    runningStored?: boolean
    hostStatus?: string
    argumentsOnly?: boolean
    foreignResponse?: boolean
    missingModel?: boolean
    noTools?: boolean
    variant?: string
    modelVariants?: string[]
    retain?: boolean
    wrongLocation?: boolean
    activeQuartermaster?: boolean
    stepUsage?: boolean
    stepIteratorThrows?: boolean
    stepCloseFails?: "reject" | "throw"
    subscribeThrows?: boolean
    planRouting?: ReviewerConfig["planRouting"]
    planRoutingRejected?: boolean
    selection?: unknown
    systemOne?: boolean
    activationFailed?: boolean
    failFirstActivation?: boolean
    activationDelayed?: boolean
    holdPrompt?: () => Promise<void> | void
    missingSession?: "name" | "dotted" | "present"
    activationRepresentation?: "directory-slash" | "file-url" | "id-only" | "id-new-path"
    mcpServers?: boolean | "after-first"
    pluginMcp?: boolean
    hostFollowUpStep?: boolean
    agreeingDuplicate?: boolean
    providerError?: boolean
    rejectedFollowUp?: boolean
    blindSteps?: number
  } = {},
) {
  let reasked = false
  // True for each later step of a turn that the reviewer closed without re-asking.
  const followUps: boolean[] = []
  const closed = (event: ContextEvent) =>
    Object.keys(event.tools).length === 0 &&
    !JSON.stringify([event.system, event.messages]).includes("exactly once")
  const isolationBase = mkdtempSync(join(tmpdir(), "prb-isolation-"))
  const previousIsolationBase = process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
  process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = isolationBase
  let tool!: Tool
  let contextHook!: (event: ContextEvent) => void
  const sessionHooks = new Map<string, (event: never) => unknown>()
  let toolHook!: (event: { sessionID: string; tool: string }) => void
  let directory = ""
  let requestedVariant: string | undefined
  let requestedModel: unknown
  const rpcCalls: unknown[] = []
  const directories: string[] = []
  const activated = new Set<unknown>()
  let sessionID = ""
  const sessionIDs: string[] = []
  const removed = new Set<string>()
  const messagesBySession = new Map<string, string>()
  const attempts: ReviewAttempt[] = []
  let prompts = 0
  const forcedFrames: boolean[] = []
  let mcpLists = 0
  const mcpTransforms: Array<(editor: McpEditor) => void> = []
  let disposed = 0
  let checks = 0
  let setups = 0
  let pluginID = ""
  let hostCleanup: (() => Promise<void>) | undefined
  // Registrations made by the current bootstrap setup, which the host disposes on unload.
  const scope: Array<{ dispose(): Promise<void> }> = []
  const registration = (onDispose = () => void disposed++) => {
    let active = true
    const handle = {
      dispose: async () => {
        if (active) onDispose()
        active = false
      },
    }
    scope.push(handle)
    return handle
  }
  const usageReports: unknown[] = []
  const stepEvents: unknown[] = []
  let wakeSteps: (() => void) | undefined
  const subscribe = ({ signal }: { signal: AbortSignal }) =>
    (async function* () {
      while (!signal.aborted) {
        if (stepEvents.length > 0) {
          yield stepEvents.shift()
          continue
        }
        await new Promise<void>((resolve) => {
          wakeSteps = resolve
          signal.addEventListener("abort", () => resolve(), { once: true })
        })
      }
    })()
  const closeFails = (stream: AsyncGenerator<unknown>) => ({
    [Symbol.asyncIterator]: () => ({
      next: () => stream.next(),
      return: () => {
        void stream.return(undefined)
        if (options.stepCloseFails === "throw") throw new Error("event stream close failed")
        return Promise.reject(new Error("event stream close failed"))
      },
    }),
  })
  const ctx = {
    location: { directory: "/workspace/operational" },
    ...(options.stepUsage
      ? {
          event: {
            subscribe: options.stepIteratorThrows
              ? () => ({
                  [Symbol.asyncIterator]() {
                    throw new Error("event stream initialization failed")
                  },
                })
              : options.stepCloseFails
                ? (input: { signal: AbortSignal }) => closeFails(subscribe(input))
                : subscribe,
          },
        }
      : {}),
    ...(options.subscribeThrows
      ? {
          event: {
            subscribe: () => {
              throw new Error("event bus unavailable")
            },
          },
        }
      : {}),
    rpc: (definition: { id: string }) => ({
      selectPlan: async (input: unknown) => {
        expect(definition.id).toBe("quartermaster")
        expect(sessionIDs).toHaveLength(rpcCalls.length)
        rpcCalls.push(input)
        if (!options.planRouting) throw new Error("Static reviews must not query Quartermaster")
        return options.selection
      },
      reportDirectUsage: async (input: unknown) => {
        expect(definition.id).toBe("quartermaster")
        usageReports.push(input)
        return { status: "accepted" }
      },
    }),
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
      hook: async (name: string, callback: (event: never) => unknown) => {
        sessionHooks.set(name, callback)
        if (name === "context") contextHook = callback as typeof contextHook
        return registration()
      },
    },
    mcp: {
      transform: async (callback: (editor: McpEditor) => void) => {
        mcpTransforms.push(callback)
        return registration(() => void mcpTransforms.splice(mcpTransforms.indexOf(callback), 1))
      },
    },
  } as unknown as Context
  const client = {
    plugin: {
      list: async (input: { location: { directory: string } }) => {
        directory = input.location.directory
        checks++
        {
          // The host re-reads a rewritten bootstrap file; a module cache would not.
          const evaluated = join(directory, `index.${checks}.js`)
          await copyFile(join(directory, "index.js"), evaluated)
          const plugin = await import(pathToFileURL(evaluated).href)
          pluginID = plugin.default.id
          // Matching bytes keep their timestamp, so a new location is a new activation.
          const generation = (
            globalThis as unknown as Record<symbol, Map<string, unknown> | undefined>
          )[Symbol.for("opencode-permission-reviewer.isolated-activation")]?.get("isolation")
          if (!generation) throw new Error("isolation activation missing")
          if (!activated.has(generation)) {
            scope.length = 0
            hostCleanup = await plugin.default.setup({ ...ctx, location: { directory } })
            activated.add(generation)
            directories.push(directory)
            setups++
          }
        }
        if (options.activationFailed || (options.failFirstActivation && setups === 1))
          return {
            data: [
              {
                source: { type: "local", path: directory + "/index.js" },
                state: { status: "failed", error: "Fixture activation failure" },
              },
            ],
          }
        if (options.activationDelayed && checks < 3) return { data: [] }
        const sourcePath =
          options.activationRepresentation === "directory-slash"
            ? directory + "/"
            : options.activationRepresentation === "file-url"
              ? pathToFileURL(directory + "/index.js").href
              : options.activationRepresentation === "id-new-path"
                ? `plugin://${pluginID}`
                : directory + "/index.js"
        return {
          data: [
            ...(options.activeQuartermaster
              ? [{ id: "quartermaster", state: { status: "active" } }]
              : []),
            {
              id: pluginID,
              source:
                options.activationRepresentation === "id-only"
                  ? { type: "local" }
                  : { type: "local", path: sourcePath },
              state: { status: "active" },
            },
          ],
        }
      },
    },
    model: {
      list: async () => ({
        data: options.missingModel
          ? []
          : ["reviewer", "selected"].map((id) => ({
              providerID: "fixture",
              id,
              capabilities: { tools: !options.noTools },
              variants: (options.modelVariants ?? ["max"]).map((id) => ({ id })),
            })),
      }),
    },
    mcp: {
      list: async (input: { location: { directory: string } }) => {
        expect(input.location.directory).toBe(directory)
        mcpLists++
        const servers = new Map<string, McpServer>()
        const editor: McpEditor = {
          list: () => [...servers],
          get: (name) => servers.get(name),
          // The host stores a mutable copy of each config, so the fixture does too.
          set: (name, config) => void servers.set(name, structuredClone(config) as McpServer),
          update: () => {},
          remove: (name) => void servers.delete(name),
        }
        // A global plugin set up earlier adds a server, as @upstash/context7-opencode does.
        if (options.pluginMcp)
          editor.set("context7", { type: "remote", url: "https://mcp.invalid/mcp" })
        for (const transform of mcpTransforms) transform(editor)
        // Added after every transform, so the fail-closed inventory tests still see a server.
        if (options.mcpServers === true || (options.mcpServers === "after-first" && mcpLists > 1))
          servers.set("fixture", { type: "remote", url: "https://fixture.invalid/mcp" })
        return { location: input.location, data: [...servers.keys()].map((name) => ({ name })) }
      },
    },
    session: {
      create: async (input: {
        id: string
        agent?: string
        location: { directory: string }
        model: { variant?: string }
        permissions: unknown[]
      }) => {
        sessionID = input.id
        requestedVariant = input.model.variant
        requestedModel = input.model
        sessionIDs.push(sessionID)
        expect(input.agent).toBeUndefined()
        expect(input.permissions[0]).toEqual({ action: "*", resource: "*", effect: "deny" })
        for (const action of ["read", "shell"])
          expect(input.permissions).not.toContainEqual({ action, resource: "*", effect: "ask" })
        return {
          id: sessionID,
          agent: "build",
          location: { directory: options.wrongLocation ? "/workspace/operational" : directory },
        }
      },
      prompt: async ({ sessionID: current }: { sessionID: string }) => {
        await options.holdPrompt?.()
        prompts++
        if (options.stepUsage) {
          stepEvents.push({
            id: `evt_${current}_${prompts}`,
            type: "session.step.ended",
            created: prompts,
            data: {
              sessionID: current,
              assistantMessageID: "message_result",
              tokens: { input: 100, output: 20, reasoning: 5, cache: { read: 40, write: 0 } },
            },
          })
          wakeSteps?.()
        }
        const readDefinition = { description: "Native read schema" }
        const shellDefinition = { description: "Native shell schema" }
        const event: ContextEvent = {
          sessionID: current,
          system: ["UNTRUSTED_SYSTEM"],
          messages: ["UNTRUSTED_HISTORY"],
          tools: {
            permission_reviewer_result: tool,
            read: readDefinition,
            shell: shellDefinition,
            execute: {},
            edit: {},
          },
          ...(options.lowBudget ? { options: { maxTokens: 16 } } : {}),
        }
        contextHook(event)
        if (options.lowBudget) {
          expect(event.options?.maxTokens).toBeGreaterThanOrEqual(16384)
          const request = new Request("https://api.openai.com/v1/responses", {
            method: "POST",
            headers: { "content-type": "application/json", "content-length": "4" },
            body: JSON.stringify({
              model: "gpt-6-luna",
              input: [],
              max_output_tokens: 64,
              tools: [{ type: "function", name: "permission_reviewer_result" }],
            }),
          })
          const outgoing = {
            sessionID: current,
            kind: "primary",
            model: {},
            request,
          }
          await sessionHooks.get("http.request")?.(outgoing as never)
          const sent = JSON.parse(await outgoing.request.clone().text())
          expect(sent.max_output_tokens).toBeGreaterThanOrEqual(16384)
          expect(sent.tool_choice).toEqual({
            type: "function",
            name: "permission_reviewer_result",
          })
          expect(outgoing.request.headers.get("content-length")).toBeNull()
        }
        messagesBySession.set(current, JSON.stringify(event.messages))
        // OpenAI Responses requests go over the session socket, not the HTTP hook.
        const socket = {
          sessionID: current,
          kind: "primary",
          frame: JSON.stringify({
            type: "response.create",
            input: [],
            tools: [{ type: "function", name: "permission_reviewer_result" }],
          }),
        }
        await sessionHooks.get("experimental.ws.send")?.(socket as never)
        const sentFrame = JSON.parse(socket.frame)
        forcedFrames.push(
          sentFrame.tool_choice?.name === "permission_reviewer_result" &&
            sentFrame.parallel_tool_calls === false,
        )
        expect(JSON.stringify(event.system)).not.toContain("UNTRUSTED_SYSTEM")
        expect(JSON.stringify(event.messages)).not.toContain("UNTRUSTED_HISTORY")
        expect(event.tools.shell).toBeUndefined()
        expect(event.tools.execute).toBeUndefined()
        expect(event.tools.edit).toBeUndefined()
        expect(event.tools.read).toBeUndefined()
        for (const prompt of [event.system, event.messages])
          expect(JSON.stringify(prompt)).not.toContain("Do not call read, shell")
        // Model dispatch must pass execute.before before any permission request or file access.
        for (const name of ["read", "shell"]) {
          let executed = false
          let permissionRequested = false
          expect(() => {
            toolHook({ sessionID: current, tool: name })
            permissionRequested = true
            executed = true
          }).toThrow("Operational tools")
          expect(executed).toBe(false)
          expect(permissionRequested).toBe(false)
        }
        expect(() => toolHook({ sessionID: current, tool: "shell" })).toThrow("Operational tools")
        expect(() => toolHook({ sessionID: current, tool: "execute" })).toThrow("Operational tools")
        if (
          options.format !== "text" &&
          !options.invalid &&
          options.textBody === undefined &&
          options.reasoningBody === undefined &&
          options.toolError === undefined &&
          options.toolErrors === undefined &&
          !options.argumentsOnly &&
          !options.providerError
        ) {
          await tool.execute(tool.input.parse(decision("allow")), { sessionID: current })
          if (options.agreeingDuplicate)
            await tool.execute(
              { ...decision("allow"), rationale: "The same decision, worded again.", confidence: 0.75 },
              { sessionID: current },
            )
          if (options.ambiguous)
            await expect(tool.execute(decision("deny"), { sessionID: current })).rejects.toThrow(
              "ambiguous",
            )
        }
        if (options.hostFollowUpStep) {
          // The host continues after a tool call and builds a context for that step.
          const next: ContextEvent = {
            sessionID: current,
            system: ["UNTRUSTED_SYSTEM"],
            messages: ["UNTRUSTED_HISTORY"],
            tools: { permission_reviewer_result: tool },
          }
          contextHook(next)
          expect(next.tools).toEqual({})
          reasked = JSON.stringify([next.system, next.messages]).includes("exactly once")
        }
        if (options.rejectedFollowUp) {
          // The host runs another step after a rejected call, and its history shows the call.
          const next: ContextEvent = {
            sessionID: current,
            system: ["UNTRUSTED_SYSTEM"],
            messages: [
              { role: "user", content: [{ type: "text", text: "evidence" }] },
              {
                role: "assistant",
                content: [
                  {
                    type: "tool-call",
                    id: "call_result",
                    name: "permission_reviewer_result",
                    input: {},
                  },
                ],
              },
              {
                role: "tool",
                content: [
                  {
                    type: "tool-result",
                    id: "call_result",
                    name: "permission_reviewer_result",
                    result: { type: "error", value: "Invalid" },
                  },
                ],
              },
            ],
            tools: { permission_reviewer_result: tool },
          }
          contextHook(next)
          followUps.push(closed(next))
        }
        for (let step = 0; step < (options.blindSteps ?? 0); step++) {
          // A history that does not show the call still stops at the step cap.
          const next: ContextEvent = {
            sessionID: current,
            system: ["UNTRUSTED_SYSTEM"],
            messages: ["UNTRUSTED_HISTORY"],
            tools: { permission_reviewer_result: tool },
          }
          contextHook(next)
          followUps.push(closed(next))
        }
        return { id: "inbox_fixture" }
      },
      wait: async () => {},
      context: async () => [
        {
          type: "user",
          id: options.foreignResponse ? "inbox_other" : "inbox_fixture",
          text: "evidence",
        },
        {
          type: "assistant",
          id: "message_result",
          ...(options.providerError
            ? { error: { type: "api", status: 400, message: "Unsupported parameter: tool_choice" } }
            : {}),
          content: options.providerError
            ? []
            : options.reasoningBody !== undefined &&
            options.textBody === undefined &&
            options.toolError === undefined &&
            options.toolErrors === undefined
              ? [{ type: "reasoning", text: options.reasoningBody }]
              : options.textBody !== undefined
              ? [
                  ...(options.reasoningBody !== undefined
                    ? [{ type: "reasoning", text: options.reasoningBody }]
                    : []),
                  { type: "text", text: options.textBody },
                ]
              : options.toolErrors !== undefined
                ? options.toolErrors.map((input, index) => ({
                    type: "tool",
                    id: `call_${index}`,
                    name: "permission_reviewer_result",
                    state: {
                      status: "error",
                      input,
                      error: { type: "validation", message: "Invalid" },
                    },
                  }))
                : options.toolError !== undefined
                  ? [
                      {
                        type: "tool",
                        id: "call_result",
                        name: "permission_reviewer_result",
                        state: {
                          status: "error",
                          input: options.toolError,
                          error: { type: "validation", message: "Invalid" },
                        },
                      },
                    ]
                  : options.format === "text"
                    ? [
                        {
                          type: "text",
                          text: options.invalid
                            ? "not a decision"
                            : JSON.stringify(decision("allow")),
                        },
                      ]
                    : [
                        {
                          type: "tool",
                          id: "call_result",
                          name: "permission_reviewer_result",
                          state: {
                            status:
                              options.hostStatus ??
                              (options.runningStored
                                ? "running"
                                : options.streamingStored
                                  ? "streaming"
                                  : "completed"),
                            ...(options.argumentsOnly || options.hostFollowUpStep
                              ? { input: decision("allow") }
                              : {}),
                          },
                        },
                        // A re-asked model reviews again and calls the tool the host no
                        // longer offers; its rationale differs from the stored decision.
                        ...(reasked
                          ? [
                              {
                                type: "tool",
                                id: "call_again",
                                name: "permission_reviewer_result",
                                state: {
                                  status: "error",
                                  input: { ...decision("allow"), rationale: "Second independent review" },
                                  error: { type: "unknown", message: "Tool not available" },
                                },
                              },
                            ]
                          : []),
                      ],
        },
      ],
      interrupt: async () => {},
      remove: async ({ sessionID: current }: { sessionID: string }) => {
        removed.add(current)
      },
      get: async ({ sessionID: current }: { sessionID: string }) => {
        if (removed.has(current)) {
          if (options.missingSession === "present") return { id: current }
          if (options.missingSession === "name") {
            throw Object.assign(new Error("SessionNotFoundError: session is gone"), {
              name: "SessionNotFoundError",
            })
          }
          if (options.missingSession === "dotted") {
            throw { _tag: "Session.NotFoundError", message: "Session not found" }
          }
          throw { _tag: "SessionNotFoundError" }
        }
        return { id: current }
      },
    },
  } as unknown as OpenCodeClient
  const backend = createV2ReviewerBackend(
    ctx,
    config({
      model: "fixture/reviewer",
      variant: options.variant ?? "max",
      outputFormat: options.format ?? "json_schema",
      retainReviewSessions: options.retain ?? false,
      ...(options.planRouting ? { planRouting: options.planRouting } : {}),
      ...(options.planRoutingRejected ? { planRoutingRejected: true } : {}),
      ...(options.systemOne
        ? {
            model: "opencode/jev-1.13-free",
            escalationReviewer: {
              model: "fixture/reviewer",
              variant: "max",
              outputFormat: options.format ?? "json_schema",
              timeoutMs: 5000,
            },
          }
        : {}),
    }),
  )
  const envelope: ReviewEnvelope = {
    request: request(),
    directory: "/workspace/operational",
    worktree: "/workspace/operational",
    transcript: "Run printf safe",
    intentHistory: "Run printf safe",
    enrichment: "",
    sshAudit: [],
  }
  return {
    backend,
    run: (command = "Run printf safe") => {
      const attempt = new ReviewAttempt("generation_fixture", 5000)
      attempts.push(attempt)
      return backend.review(
        { ...envelope, transcript: command, intentHistory: command },
        attempt,
        client,
      )
    },
    state: () => ({
      directory,
      directories: [...directories],
      sessionID,
      sessionIDs,
      removed: removed.has(sessionID),
      requestedVariant,
      requestedModel,
      rpcCalls,
      usageReports: [...usageReports],
      messagesBySession,
      prompts,
      forcedFrames: [...forcedFrames],
      followUps: [...followUps],
      mcpLists,
      mcpTransforms: mcpTransforms.length,
      disposed,
      setups,
    }),
    mcp: async () => (await client.mcp.list({ location: { directory } })).data,
    reload: async () => {
      await hostCleanup?.()
      await Promise.all(scope.splice(0).map((handle) => handle.dispose()))
      const plugin = await import(pathToFileURL(directory + "/index.js").href)
      hostCleanup = await plugin.default.setup({ ...ctx, location: { directory } })
      setups++
    },
    guard: (id: string, name = "shell") => toolHook({ sessionID: id, tool: name }),
    unrelated: () => {
      const event: ContextEvent = {
        sessionID: "ses_other",
        system: [],
        messages: [],
        tools: { permission_reviewer_result: tool, shell: {} },
      }
      contextHook(event)
      expect(event.tools.permission_reviewer_result).toBeUndefined()
      expect(event.tools.shell).toBeDefined()
      toolHook({ sessionID: "ses_other", tool: "shell" })
      return tool.execute(decision("allow"), { sessionID: "ses_other" })
    },
    cleanup: async () => {
      for (const attempt of attempts) attempt.close("cancelled")
      await backend.dispose()
      for (const path of directories) if (existsSync(path)) await rm(path, { recursive: true })
      if (existsSync(isolationBase)) await rm(isolationBase, { recursive: true })
      await rm(`${isolationBase}.owner`, { force: true })
      if (previousIsolationBase === undefined)
        delete process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
      else process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = previousIsolationBase
    },
  }
}

test("isolated structured and text backends preserve scope, variant, and retention", async () => {
  for (const format of ["json_schema", "text"] as const) {
    const harness = fixture({ format, variant: "max", retain: format === "text" })
    try {
      expect((await harness.run()).kind).toBe("allow")
      const state = harness.state()
      expect(state.prompts).toBe(1)
      expect(state.rpcCalls).toEqual([])
      expect(state.removed).toBe(format !== "text")
      expect(state.disposed).toBe(0)
      expect(harness.backend.owns(state.sessionID)).toBe(false)
      expect(existsSync(state.directory + "/index.js")).toBe(true)
      await expect(harness.unrelated()).rejects.toThrow("Not an active")
    } finally {
      await harness.cleanup()
    }
  }
})

const planRouting = { plan: "review", models: ["fixture/selected"] }
const planSelection = {
  apiVersion: 1,
  status: "selected",
  reasonCode: "first-eligible",
  reason: "Selected",
  skipped: [],
  plan: { id: "review", source: "named-plan", reasonCode: "named-plan" },
  selected: { providerID: "fixture", modelID: "selected", variant: "max" },
}

test("named plan is queried before each new reviewer without assigning an agent", async () => {
  const harness = fixture({ planRouting, selection: planSelection })
  try {
    for (let i = 0; i < 2; i++) {
      const result = await harness.run()
      expect(result.kind).toBe("allow")
      expect(result.reviewerModel).toBe("fixture/selected")
    }
    expect(harness.state().rpcCalls).toEqual([{ plan: "review" }, { plan: "review" }])
    expect(harness.state().requestedModel).toEqual({
      providerID: "fixture",
      id: "selected",
      variant: "max",
    })
  } finally {
    await harness.cleanup()
  }
})

test("named plan failures never create a reviewer or use the static model", async () => {
  for (const selection of [
    {},
    { ...planSelection, status: "no-plan" },
    { ...planSelection, status: "no-eligible" },
    { ...planSelection, apiVersion: 2 },
    { ...planSelection, plan: { ...planSelection.plan, id: "other" } },
    { ...planSelection, selected: { providerID: "fixture", modelID: "reviewer" } },
    { ...planSelection, selected: { providerID: "fixture/selected", modelID: "" } },
    { ...planSelection, selected: { ...planSelection.selected, variant: "unsupported" } },
  ]) {
    const harness = fixture({ planRouting, selection })
    try {
      expect((await harness.run()).kind).toBe("escalate")
      expect(harness.state().sessionIDs).toEqual([])
    } finally {
      await harness.cleanup()
    }
  }
})

test("Jev reasoning escalation uses its configured model without agent routing", async () => {
  const previousKey = process.env.OPENCODE_API_KEY
  const previousFetch = globalThis.fetch
  process.env.OPENCODE_API_KEY = "synthetic-opencode-key"
  let fetches = 0
  const answers = Object.fromEntries(
    Object.entries(SYSTEM_ONE_QUESTIONS).map(([name, question]) => {
      if (question.type === "noul")
        return [
          name,
          {
            type: "noul",
            noul: ["material_authorization", "within_intent_scope"].includes(name) ? 1 : 0,
          },
        ]
      const keys = Object.keys(question.criteria)
      const selected = name === "outcome" ? "escalate" : keys[0]
      const confidence = name === "outcome" ? 0.6 : 1
      return [
        name,
        {
          type: "choice",
          choice: selected,
          confidence,
          probabilities: Object.fromEntries(
            keys.map((key) => [
              key,
              key === selected ? confidence : (1 - confidence) / (keys.length - 1),
            ]),
          ),
        },
      ]
    }),
  )
  globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    expect(JSON.parse(String(init?.body)).model).toBe("jev-1.13-free")
    fetches++
    return Response.json({ model: "jev-1.13-free", answers })
  }) as typeof fetch
  try {
    for (const routed of [false, true]) {
      const harness = fixture({
        systemOne: true,
        ...(routed ? { planRouting, selection: planSelection } : {}),
      })
      try {
        const result = await harness.run()
        const state = harness.state()
        expect(result.kind).toBe("allow")
        expect(result.reviewerEscalatedFrom?.model).toBe("opencode/jev-1.13-free")
        expect(state.rpcCalls).toEqual(routed ? [{ plan: "review" }] : [])
        expect(state.prompts).toBe(1)
        expect(state.sessionIDs).toHaveLength(1)
        {
          expect(result.reviewerModel).toBe(routed ? "fixture/selected" : "fixture/reviewer")
          expect(state.requestedModel).toEqual({
            providerID: "fixture",
            id: routed ? "selected" : "reviewer",
            variant: "max",
          })
        }
      } finally {
        await harness.cleanup()
      }
    }
    expect(fetches).toBe(2)
  } finally {
    globalThis.fetch = previousFetch
    if (previousKey === undefined) delete process.env.OPENCODE_API_KEY
    else process.env.OPENCODE_API_KEY = previousKey
  }
})

test("a short provider budget is raised and the decision tool is required", () => {
  expect(
    forceReviewerCompletion({
      input: [],
      max_output_tokens: 64,
      tools: [{ type: "function", name: "permission_reviewer_result" }],
    }),
  ).toMatchObject({
    max_output_tokens: 16384,
    tool_choice: { type: "function", name: "permission_reviewer_result" },
  })
  expect(
    forceReviewerCompletion({
      messages: [],
      max_tokens: 32,
      tools: [{ type: "function", function: { name: "permission_reviewer_result" } }],
    }),
  ).toMatchObject({
    max_tokens: 16384,
    tool_choice: { type: "function", function: { name: "permission_reviewer_result" } },
  })
  expect(
    forceReviewerCompletion({
      messages: [],
      tools: [{ type: "function", function: { name: "shell" } }],
    }),
  ).toBeUndefined()
})

test("a reasoning model can leave the only decision in reasoning, and a short budget is raised", async () => {
  const reasoning = fixture({ reasoningBody: JSON.stringify(decision("allow")) })
  try {
    const result = await reasoning.run()
    expect(result.kind).toBe("allow")
    expect(reasoning.state().prompts).toBe(1)
  } finally {
    await reasoning.cleanup()
  }
  const buried = fixture({
    reasoningBody: JSON.stringify(decision("allow")),
    textBody: `The decision is:\n${JSON.stringify(decision("allow"))}`,
  })
  try {
    expect((await buried.run()).kind).toBe("escalate")
    expect(buried.state().prompts).toBe(3)
  } finally {
    await buried.cleanup()
  }
  const budget = fixture({ lowBudget: true })
  try {
    expect((await budget.run()).kind).toBe("allow")
  } finally {
    await budget.cleanup()
  }
})

test("a structured reviewer accepts one normalized decision from text or a rejected tool call", async () => {
  const loose = {
    ...decision("allow"),
    version: "2",
    outcome: "Allow",
    confidence: "0.95",
    script_analysis: "too short",
    commentary: "ignored",
  }
  const text = fixture({ textBody: JSON.stringify(loose) })
  try {
    const result = await text.run()
    expect(result.kind).toBe("allow")
    expect(result.decision?.script_analysis).toBeUndefined()
    expect(text.state().prompts).toBe(1)
  } finally {
    await text.cleanup()
  }
  const rejected = fixture({ toolError: loose })
  try {
    const result = await rejected.run()
    expect(result.kind).toBe("allow")
    expect(result.decision?.version).toBe(2)
    expect(rejected.state().prompts).toBe(1)
  } finally {
    await rejected.cleanup()
  }
  const prose = fixture({
    textBody: `The decision is:\n${JSON.stringify(decision("allow"))}`,
  })
  try {
    expect((await prose.run()).kind).toBe("escalate")
    expect(prose.state().prompts).toBe(3)
  } finally {
    await prose.cleanup()
  }
  const conflict = fixture({
    toolErrors: [decision("allow"), decision("deny")],
  })
  try {
    expect((await conflict.run()).kind).toBe("escalate")
    expect(conflict.state().prompts).toBe(1)
  } finally {
    await conflict.cleanup()
  }
})

test("one decision stands whatever label the host has put on the tool call", async () => {
  for (const options of [
    { hostStatus: "settling" },
    { hostStatus: "settling", argumentsOnly: true },
  ]) {
    const harness = fixture(options)
    try {
      const result = await harness.run()
      expect(result.kind).toBe("allow")
      expect(result.decisionSource).toBe("llm-reviewer")
      expect(harness.state().prompts).toBe(1)
    } finally {
      await harness.cleanup()
    }
  }
})

test("a stored decision still counts when the host leaves the tool call running", async () => {
  const harness = fixture({ runningStored: true })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("allow")
    expect(result.decisionSource).toBe("llm-reviewer")
    expect(harness.state().prompts).toBe(1)
  } finally {
    await harness.cleanup()
  }
})

test("a stored decision still counts when the host leaves the tool call streaming", async () => {
  const harness = fixture({ streamingStored: true })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("allow")
    expect(result.decisionSource).toBe("llm-reviewer")
    expect(harness.state().prompts).toBe(1)
  } finally {
    await harness.cleanup()
  }
})

test("the host's follow-up step after the decision does not re-ask the review", async () => {
  const harness = fixture({ hostFollowUpStep: true })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("allow")
    expect(result.decisionSource).toBe("llm-reviewer")
    expect(harness.state().prompts).toBe(1)
  } finally {
    await harness.cleanup()
  }
})

test("a rejected decision call closes the turn instead of repeating it", async () => {
  // The tool schema rejects a string version; the review loop normalizes it.
  const harness = fixture({
    toolError: { ...decision("allow"), version: "2" },
    rejectedFollowUp: true,
  })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("allow")
    expect(result.decision?.version).toBe(2)
    expect(harness.state().prompts).toBe(1)
    expect(harness.state().followUps).toEqual([true])
  } finally {
    await harness.cleanup()
  }
})

test("the step cap closes a turn whose history does not show the call", async () => {
  const harness = fixture({ toolError: { ...decision("allow"), version: 3 }, blindSteps: 3 })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("escalate")
    expect(result.reason).toContain("the decision call had invalid arguments")
    expect(harness.state().prompts).toBe(3)
    // Each turn sends the review twice more, then closes; every new turn starts over.
    expect(harness.state().followUps).toEqual([
      false, false, true,
      false, false, true,
      false, false, true,
    ])
  } finally {
    await harness.cleanup()
  }
})

test("more decision calls than one turn allows are named in the failure", async () => {
  const harness = fixture({ toolErrors: [1, 2, 3, 4].map(() => decision("allow")) })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("escalate")
    expect(result.reason).toContain("too many decision calls (4)")
    expect(harness.state().prompts).toBe(1)
  } finally {
    await harness.cleanup()
  }
})

test("the socket frame requires one decision call, and other wire formats are left alone", () => {
  expect(
    forceReviewerFrame({
      type: "response.create",
      input: [],
      tools: [{ type: "function", name: "permission_reviewer_result" }],
    }),
  ).toMatchObject({
    tool_choice: { type: "function", name: "permission_reviewer_result" },
    parallel_tool_calls: false,
  })
  expect(
    forceReviewerFrame({ type: "response.create", tools: [{ type: "function", name: "shell" }] }),
  ).toBeUndefined()
  expect(forceReviewerFrame({ type: "session.update", tools: [] })).toBeUndefined()
  // Anthropic names the same tool without an OpenAI type; its body takes no OpenAI fields.
  expect(
    forceReviewerCompletion({
      messages: [],
      max_tokens: 32,
      tools: [{ name: "permission_reviewer_result", input_schema: { type: "object" } }],
    }),
  ).toBeUndefined()
})

test("decision calls that agree are one decision at the lowest confidence", async () => {
  const harness = fixture({ agreeingDuplicate: true })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("allow")
    expect(result.decision?.confidence).toBe(0.75)
    expect(harness.state().prompts).toBe(1)
    expect(harness.state().forcedFrames).toEqual([true])
  } finally {
    await harness.cleanup()
  }
})

test("a provider error is named in the failure and stops forcing the tool", async () => {
  const harness = fixture({ providerError: true })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("escalate")
    expect(result.reason).toContain("provider error 400 api: Unsupported parameter: tool_choice")
    expect(harness.state().prompts).toBe(3)
    expect(harness.state().forcedFrames).toEqual([true, false, false])
  } finally {
    await harness.cleanup()
  }
})

test("a reply without a decision call says so in the failure", async () => {
  const harness = fixture({ textBody: "I reviewed it and it looks fine." })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("escalate")
    expect(result.reason).toContain("no decision call; the reply was text")
  } finally {
    await harness.cleanup()
  }
})

test("invalid, ambiguous, and foreign execution outputs never become approvals", async () => {
  for (const options of [
    { invalid: true },
    { format: "text" as const, invalid: true },
    { ambiguous: true },
    { foreignResponse: true },
    { format: "text" as const, foreignResponse: true },
  ]) {
    const harness = fixture(options)
    try {
      expect((await harness.run()).kind).toBe("escalate")
      expect(harness.state().prompts).toBeLessThanOrEqual(3)
      expect(harness.state().removed).toBe(true)
    } finally {
      await harness.cleanup()
    }
  }
})

test("isolation activation waits for the host report and fails loudly", async () => {
  const delayed = fixture({ activationDelayed: true })
  try {
    expect((await delayed.run()).kind).toBe("allow")
    expect(delayed.state().prompts).toBe(1)
    expect(delayed.state().setups).toBe(1)
  } finally {
    await delayed.cleanup()
  }
  const failed = fixture({ activationFailed: true })
  try {
    const result = await failed.run()
    expect(result.kind).toBe("escalate")
    expect(result.reason).toContain("failed to activate")
    expect(failed.state().prompts).toBe(0)
  } finally {
    await failed.cleanup()
  }
})

test("a failed isolation bootstrap is retried in a new location", async () => {
  const harness = fixture({ failFirstActivation: true })
  try {
    const first = await harness.run()
    expect(first.kind).toBe("escalate")
    expect(first.reason).toContain("failed to activate")
    expect(harness.state().directories).toHaveLength(1)
    expect(harness.state().disposed).toBe(5)
    const failedDirectory = harness.state().directory

    const second = await harness.run()
    expect(second.kind).toBe("allow")
    const recovered = harness.state()
    expect(recovered.setups).toBe(2)
    expect(recovered.disposed).toBe(5)
    expect(recovered.directories).toHaveLength(2)
    expect(recovered.directory).toBe(failedDirectory)
    expect(existsSync(failedDirectory + "/opencode.json")).toBe(true)
  } finally {
    await harness.cleanup()
  }
})

test("backend disposal releases hooks registered by a later location activation", async () => {
  const harness = fixture()
  try {
    expect((await harness.run()).kind).toBe("allow")
    await harness.reload()
    expect(harness.state().disposed).toBe(5)
    expect((await harness.run()).kind).toBe("allow")
    await harness.backend.dispose()
    expect(harness.state().disposed).toBe(10)
    expect(existsSync(harness.state().directory + "/opencode.json")).toBe(true)
  } finally {
    await harness.cleanup()
  }
})

test("isolation activation accepts normalized local plugin representations", async () => {
  for (const activationRepresentation of [
    "directory-slash",
    "file-url",
    "id-only",
    "id-new-path",
  ] as const) {
    const harness = fixture({ activationRepresentation })
    try {
      expect((await harness.run()).kind).toBe("allow")
      expect(harness.state().prompts).toBe(1)
    } finally {
      await harness.cleanup()
    }
  }
})

test("unavailable model, unsupported format or variant, and wrong isolation fail before prompting", async () => {
  for (const options of [
    { missingModel: true },
    { noTools: true },
    { variant: "unsupported" },
    { wrongLocation: true },
    { activeQuartermaster: true },
  ]) {
    const harness = fixture(options)
    try {
      expect((await harness.run()).kind).toBe("escalate")
      expect(harness.state().prompts).toBe(0)
      expect(existsSync(harness.state().directory + "/opencode.json")).toBe(true)
    } finally {
      await harness.cleanup()
    }
  }
})

test("the default variant falls back to the model default when the model lacks it", async () => {
  for (const modelVariants of [[], ["low", "high"]]) {
    const harness = fixture({ variant: DEFAULT_CONFIG.variant, modelVariants })
    try {
      expect((await harness.run()).kind).toBe("allow")
      expect(harness.state().prompts).toBe(1)
      expect(harness.state().requestedVariant).toBeUndefined()
    } finally {
      await harness.cleanup()
    }
  }
  const offered = fixture({ variant: DEFAULT_CONFIG.variant, modelVariants: ["medium", "high"] })
  try {
    expect((await offered.run()).kind).toBe("allow")
    expect(offered.state().requestedVariant).toBe(DEFAULT_CONFIG.variant)
  } finally {
    await offered.cleanup()
  }
})

test("an explicit variant the model lacks fails closed with the offered variants", async () => {
  const harness = fixture({ variant: "max", modelVariants: ["low", "high"] })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("escalate")
    expect(result.reason).toContain('variant "max" is unavailable (model offers: low, high)')
    expect(harness.state().prompts).toBe(0)
  } finally {
    await harness.cleanup()
  }
})

test("review sessions share one MCP-free location without mixing concurrent evidence", async () => {
  const harness = fixture()
  try {
    const commands = Array.from({ length: 16 }, (_, index) => `Review unique marker[${index}]`)
    const results = await Promise.all(commands.map((command) => harness.run(command)))
    expect(results.every((result) => result.kind === "allow")).toBe(true)
    const state = harness.state()
    expect(state.setups).toBe(1)
    expect(new Set(state.sessionIDs).size).toBe(commands.length)
    const captured = state.sessionIDs.map((id) => state.messagesBySession.get(id) ?? "")
    const markers = captured.map((message) => {
      const matches = commands.filter((command) => message.includes(command))
      expect(matches).toHaveLength(1)
      return matches[0]
    })
    expect(new Set(markers)).toEqual(new Set(commands))
    const isolatedConfig = JSON.parse(await readFile(state.directory + "/opencode.json", "utf8"))
    expect(isolatedConfig.plugins).toEqual([
      "-opencode.config.mcp",
      "-quartermaster",
      "-opencode-usage",
      state.directory,
    ])
    expect((await harness.run("Review one more unique marker")).kind).toBe("allow")
    expect(harness.state().directory).toBe(state.directory)
    expect(harness.state().setups).toBe(1)
    await harness.backend.dispose()
    expect(harness.state().disposed).toBe(5)
    expect(existsSync(state.directory + "/opencode.json")).toBe(true)
    expect(existsSync(join(state.directory, "owner.pid"))).toBe(false)
    expect(() => harness.run()).toThrow("shutting down")
  } finally {
    await harness.cleanup()
  }
})

test("a deleted isolation location is replaced only after its reviewer sessions finish", async () => {
  let release: () => void = () => {}
  let entered = false
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  const harness = fixture({
    holdPrompt: () => {
      if (entered) return
      entered = true
      return gate
    },
  })
  try {
    const first = harness.run()
    while (!entered) await new Promise((resolve) => setTimeout(resolve, 5))
    const original = harness.state().directory
    await rm(original, { recursive: true, force: true })
    expect((await harness.run()).kind).toBe("allow")
    expect(harness.state().setups).toBe(1)
    expect(harness.state().directory).toBe(original)
    release()
    expect((await first).kind).toBe("allow")
    expect((await harness.run()).kind).toBe("allow")
    const state = harness.state()
    expect(state.setups).toBe(2)
    expect(state.directory).toBe(original)
    expect(state.directories).toEqual([original, original])
    const isolatedConfig = JSON.parse(await readFile(state.directory + "/opencode.json", "utf8"))
    expect(isolatedConfig.plugins).toEqual([
      "-opencode.config.mcp",
      "-quartermaster",
      "-opencode-usage",
      state.directory,
    ])
    expect(existsSync(original)).toBe(true)
    expect(existsSync(state.directory + "/index.js")).toBe(true)
  } finally {
    release()
    await harness.cleanup()
  }
})

test("reviewer fails closed when its isolated location contains MCP servers", async () => {
  const harness = fixture({ mcpServers: true })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("escalate")
    expect(result.reason).toContain("contains MCP servers")
    expect(harness.state().sessionIDs).toHaveLength(0)
  } finally {
    await harness.cleanup()
  }
})

test("a later MCP addition prevents another review in the shared location", async () => {
  const harness = fixture({ mcpServers: "after-first" })
  try {
    expect((await harness.run()).kind).toBe("allow")
    const result = await harness.run()
    expect(result.kind).toBe("escalate")
    expect(result.reason).toContain("contains MCP servers")
    expect(harness.state().sessionIDs).toHaveLength(1)
    expect(harness.state().mcpLists).toBe(2)
  } finally {
    await harness.cleanup()
  }
})

test("plugin-added MCP servers are stripped from the isolated location", async () => {
  const harness = fixture({ pluginMcp: true })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("allow")
    expect(result.decisionSource).toBe("llm-reviewer")
    expect(harness.state().mcpTransforms).toBe(1)
    expect(harness.state().sessionIDs).toHaveLength(1)
  } finally {
    await harness.cleanup()
  }
})

test("an inert bootstrap reload keeps stripping MCP after the backend releases it", async () => {
  const harness = fixture({ pluginMcp: true })
  try {
    expect((await harness.run()).kind).toBe("allow")
    await harness.backend.dispose()
    await harness.reload()
    expect(harness.state().mcpTransforms).toBe(1)
    expect(await harness.mcp()).toEqual([])
  } finally {
    await harness.cleanup()
  }
})

test("a host SessionNotFound error without _tag still confirms cleanup", async () => {
  const harness = fixture({ missingSession: "name" })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("allow")
    expect(harness.backend.owns(harness.state().sessionID)).toBe(false)
  } finally {
    await harness.cleanup()
  }
})

test("a host Session.NotFoundError tag confirms cleanup", async () => {
  const harness = fixture({ missingSession: "dotted" })
  try {
    const result = await harness.run()
    expect(result.kind).toBe("allow")
    expect(harness.backend.owns(harness.state().sessionID)).toBe(false)
  } finally {
    await harness.cleanup()
  }
})

test("an unconfirmed reviewer session does not block the next review", async () => {
  const harness = fixture({ missingSession: "present" })
  try {
    await expect(harness.run()).rejects.toThrow("cleanup could not be confirmed")
    const stuck = harness.state().sessionID
    expect(harness.backend.owns(stuck)).toBe(true)
    expect(() => harness.guard(stuck)).toThrow("Operational tools")
    const original = harness.state().directory
    await rm(original, { recursive: true, force: true })
    await expect(harness.run()).rejects.toThrow("cleanup could not be confirmed")
    const state = harness.state()
    expect(state.directory).toBe(original)
    expect(state.setups).toBe(2)
    expect(state.sessionIDs).toHaveLength(2)
    expect(() => harness.guard(stuck)).toThrow("Operational tools")
  } finally {
    await harness.cleanup()
  }
})

test("concurrent cold starts prepare one trusted isolation folder", async () => {
  const previous = process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
  try {
    for (let round = 0; round < 10; round++) {
      const base = mkdtempSync(join(tmpdir(), "prb-cold-start-"))
      process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = base
      const results = await Promise.allSettled(
        Array.from({ length: 8 }, (_, index) => {
          // Different spellings of the same folder must use the same preparation.
          process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR =
            index % 2 === 0
              ? base
              : process.platform === "win32"
                ? base.replaceAll("\\", "/").toUpperCase()
                : `${base}/.`
          return createIsolatedLocation(async () => async () => {})
        }),
      )
      try {
        expect(results.filter((result) => result.status === "rejected")).toEqual([])
        for (const result of results) {
          if (result.status === "fulfilled") expect(existsSync(result.value.directory)).toBe(true)
        }
        expect((await readdir(base)).sort()).toEqual(["index.js", "opencode.json", "package.json"])
      } finally {
        for (const result of results) {
          if (result.status === "fulfilled") result.value.release()
        }
        await rm(base, { recursive: true, force: true })
        await rm(`${base}.owner`, { force: true })
      }
    }
  } finally {
    if (previous === undefined) delete process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
    else process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = previous
  }
})

test("failed shared-folder preparation can be retried", async () => {
  const base = mkdtempSync(join(tmpdir(), "prb-prepare-retry-"))
  const previous = process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
  process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = base
  const locations: Awaited<ReturnType<typeof createIsolatedLocation>>[] = []
  try {
    await mkdir(join(base, "index.js"))
    const failed = await Promise.allSettled(
      Array.from({ length: 4 }, () => createIsolatedLocation(async () => async () => {})),
    )
    for (const result of failed) {
      if (result.status === "fulfilled") locations.push(result.value)
    }
    expect(failed.every((result) => result.status === "rejected")).toBe(true)
    await rm(join(base, "index.js"), { recursive: true })
    const retried = await Promise.allSettled(
      Array.from({ length: 4 }, () => createIsolatedLocation(async () => async () => {})),
    )
    for (const result of retried) {
      if (result.status === "fulfilled") locations.push(result.value)
    }
    expect(retried.filter((result) => result.status === "rejected")).toEqual([])
    expect(locations).toHaveLength(4)
  } finally {
    for (const location of locations) location.release()
    if (previous === undefined) delete process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
    else process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = previous
    await rm(base, { recursive: true, force: true })
    await rm(`${base}.owner`, { force: true })
  }
})

test("a repeated isolation claim leaves trusted files and their timestamps untouched", async () => {
  const base = mkdtempSync(join(tmpdir(), "prb-stable-"))
  const previous = process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
  process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = base
  const first = await createIsolatedLocation(async () => async () => {})
  try {
    const index = join(first.directory, "index.js")
    const configPath = join(first.directory, "opencode.json")
    const past = new Date(Date.now() - 60_000)
    await utimes(index, past, past)
    await utimes(configPath, past, past)
    await writeFile(join(first.directory, "owner.pid"), "stale\n")
    const indexStamp = (await stat(index)).mtimeMs
    const configStamp = (await stat(configPath)).mtimeMs
    first.release()
    const second = await createIsolatedLocation(async () => async () => {})
    try {
      expect(second.directory).toBe(first.directory)
      expect((await stat(index)).mtimeMs).toBe(indexStamp)
      expect((await stat(configPath)).mtimeMs).toBe(configStamp)
      expect(existsSync(join(first.directory, "owner.pid"))).toBe(false)
      expect(await readFile(`${base}.owner`, "utf8")).toBe(`${process.pid}\n`)
    } finally {
      second.release()
    }
  } finally {
    first.release()
    if (previous === undefined) delete process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
    else process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = previous
    await rm(base, { recursive: true, force: true })
    await rm(`${base}.owner`, { force: true })
  }
})

test("a live owner lock reuses the trusted directory", async () => {
  const base = mkdtempSync(join(tmpdir(), "prb-owner-"))
  const previous = process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
  process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = base
  let otherAlive = false
  try {
    process.kill(process.ppid, 0)
    otherAlive = true
  } catch {
    otherAlive = false
  }
  expect(otherAlive).toBe(true)
  await writeFile(`${base}.owner`, `${process.ppid}\n`)
  const location = await createIsolatedLocation(async () => async () => {})
  try {
    expect(location.directory).toBe(base)
  } finally {
    location.release()
    if (previous === undefined) delete process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
    else process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = previous
    await rm(base, { recursive: true, force: true })
    await rm(`${base}.owner`, { force: true })
  }
})

test("a setup that ran before activation binds without rewriting the folder", async () => {
  const base = mkdtempSync(join(tmpdir(), "prb-early-"))
  const previous = process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
  process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = base
  const first = await createIsolatedLocation(async () => async () => {})
  const directory = first.directory
  const index = join(directory, "index.js")
  const stamp = (await stat(index)).mtimeMs
  first.release()
  let second: { release(): void } | undefined
  try {
    const plugin = await import(pathToFileURL(index).href)
    const ctx = {
      location: { directory },
      mcp: {
        transform: async (
          callback: (editor: { list(): []; remove(name: string): void }) => void,
        ) => {
          await callback({ list: () => [], remove: () => {} })
          return async () => {}
        },
      },
    }
    await plugin.default.setup(ctx)
    let bound = 0
    second = await createIsolatedLocation(async () => {
      bound += 1
      return async () => {}
    })
    expect(second.directory).toBe(directory)
    expect(bound).toBe(1)
    expect((await stat(index)).mtimeMs).toBe(stamp)
    await plugin.default.setup(ctx)
    expect(bound).toBe(1)
  } finally {
    second?.release()
    if (previous === undefined) delete process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
    else process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = previous
    await rm(base, { recursive: true, force: true })
    await rm(`${base}.owner`, { force: true })
  }
})

test("reviewer steps in the isolation folder are reported to Quartermaster with their model", async () => {
  const harness = fixture({ stepUsage: true, variant: "max" })
  try {
    expect((await harness.run()).kind).toBe("allow")
    for (let index = 0; index < 100 && harness.state().usageReports.length === 0; index++)
      await new Promise((resolve) => setTimeout(resolve, 5))
    const state = harness.state()
    expect(state.usageReports).toEqual([
      {
        pluginID: "opencode-permission-reviewer",
        pluginName: "OPR",
        usageID: `evt_${state.sessionID}_1:fixture/reviewer`,
        providerID: "fixture",
        modelID: "reviewer",
        variant: "max",
        counts: { input: 100, output: 20, reasoning: 5, cacheRead: 40, cacheWrite: 0 },
      },
    ])
    expect((await harness.run()).kind).toBe("allow")
    for (let index = 0; index < 100 && harness.state().usageReports.length < 2; index++)
      await new Promise((resolve) => setTimeout(resolve, 5))
    expect(harness.state().usageReports).toHaveLength(2)
  } finally {
    await harness.cleanup()
  }
})

test("usage stream initialization and close failures leak no unhandled rejection", async () => {
  for (const failure of ["iterator", "reject", "throw"] as const) {
    const unhandled: unknown[] = []
    const record = (reason: unknown) => void unhandled.push(reason)
    process.on("unhandledRejection", record)
    const harness = fixture({
      stepUsage: true,
      ...(failure === "iterator" ? { stepIteratorThrows: true } : { stepCloseFails: failure }),
    })
    try {
      expect((await harness.run()).kind).toBe("allow")
    } finally {
      await harness.cleanup()
      await new Promise((resolve) => setTimeout(resolve, 20))
      process.off("unhandledRejection", record)
    }
    expect(unhandled).toEqual([])
  }
})

test("a host that refuses the usage subscription still gets a working reviewer", async () => {
  const harness = fixture({ subscribeThrows: true })
  try {
    expect((await harness.run()).kind).toBe("allow")
    expect(harness.state().prompts).toBe(1)
  } finally {
    await harness.cleanup()
  }
})

/** Projects whose backends all claim the folder named by OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR. */
function sharedIsolationHost() {
  const name = "permission_reviewer_result"
  const handle = <T,>(list: T[], item: T) => {
    list.push(item)
    return {
      dispose: async () => {
        const index = list.indexOf(item)
        if (index >= 0) list.splice(index, 1)
      },
    }
  }
  // The host keeps one instance of the folder and runs every plugin's hooks on it.
  const instance = (directory: string) => {
    const definitions: Tool[] = []
    const contextHooks: Array<(event: ContextEvent) => void> = []
    const ctx = {
      location: { directory },
      mcp: {
        transform: async (callback: (editor: { list(): []; remove(name: string): void }) => void) => {
          callback({ list: () => [], remove: () => {} })
          return { dispose: async () => {} }
        },
      },
      tool: {
        transform: async (callback: (editor: { add(definition: Tool): void }) => void) => {
          let added!: Tool
          callback({ add: (definition) => void (added = definition) })
          return handle(definitions, added)
        },
        hook: async () => ({ dispose: async () => {} }),
      },
      session: {
        hook: async (hook: string, callback: (event: never) => unknown) =>
          hook === "context"
            ? handle(contextHooks, callback as (event: ContextEvent) => void)
            : { dispose: async () => {} },
      },
    } as unknown as Context
    return { ctx, definitions, contextHooks }
  }
  let current: ReturnType<typeof instance> | undefined
  let hostCleanup: (() => Promise<void>) | undefined
  let loading: Promise<void> | undefined
  let loads = 0
  const setUp = async (directory: string) => {
    loads++
    const plugin = await import(pathToFileURL(join(directory, "index.js")).href)
    const next = instance(directory)
    const cleanup = await plugin.default.setup(next.ctx)
    const last = hostCleanup
    current = next
    hostCleanup = cleanup
    await last?.()
  }
  const offered: string[][] = []
  const replies = new Map<string, unknown[]>()
  let held: { count: number; arrived: number; ready(): void; gate: Promise<void> } | undefined
  let release: (() => void) | undefined
  const client = {
    plugin: {
      list: async ({ location }: { location: { directory: string } }) => {
        // Projects that start together wait for the same load.
        if (!current) await (loading ??= setUp(location.directory))
        return {
          data: [
            {
              id: "permission-reviewer-isolation",
              source: { type: "local", path: join(location.directory, "index.js") },
              state: { status: "active" },
            },
          ],
        }
      },
    },
    model: {
      list: async () => ({
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
    mcp: {
      list: async (input: { location: { directory: string } }) => ({
        location: input.location,
        data: [],
      }),
    },
    session: {
      create: async (input: { id: string; location: { directory: string } }) => ({
        id: input.id,
        location: input.location,
      }),
      prompt: async ({ sessionID, text }: { sessionID: string; text: string }) => {
        const hold = held
        if (hold) {
          if (++hold.arrived === hold.count) hold.ready()
          await hold.gate
        }
        // A name-keyed registry: the last definition added is the one offered.
        const event: ContextEvent = {
          sessionID,
          system: [],
          messages: [],
          tools: { [name]: current!.definitions.at(-1), shell: {} },
        }
        for (const hook of current!.contextHooks) hook(event)
        expect(event.messages).toEqual([{ role: "user", content: [{ type: "text", text }] }])
        offered.push(Object.keys(event.tools))
        const offer = event.tools[name] as Tool | undefined
        const content: unknown[] = []
        if (offer) {
          const input = decision("allow")
          let status = "completed"
          try {
            await offer.execute(offer.input.parse(input), { sessionID })
          } catch {
            status = "error"
          }
          // Recovery from stored arguments must not hide broken tool dispatch.
          expect(status).toBe("completed")
          content.push({ type: "tool", id: "call_result", name, state: { status, input } })
        }
        replies.set(sessionID, content)
        return { id: `inbox_${sessionID}` }
      },
      wait: async () => {},
      context: async ({ sessionID }: { sessionID: string }) => [
        { type: "user", id: `inbox_${sessionID}`, text: "evidence" },
        {
          type: "assistant",
          id: `reply_${sessionID}`,
          finish: "stop",
          content: replies.get(sessionID) ?? [],
        },
      ],
      interrupt: async () => {},
      remove: async () => {},
      get: async () => {
        throw { _tag: "SessionNotFoundError" }
      },
    },
  } as unknown as OpenCodeClient
  const project = (directory: string) => ({
    directory,
    backend: createV2ReviewerBackend(
      { location: { directory }, rpc: () => ({}) } as unknown as Context,
      config({ model: "fixture/reviewer", variant: "max", outputFormat: "json_schema" }),
    ),
  })
  const attempts: ReviewAttempt[] = []
  let serial = 0
  const review = ({ backend, directory }: ReturnType<typeof project>) => {
    const attempt = new ReviewAttempt("generation_shared", 5000)
    attempts.push(attempt)
    const evidence = `Run printf safe: review evidence marker ${++serial}`
    return backend.review(
      {
        request: request(),
        directory,
        worktree: directory,
        transcript: evidence,
        intentHistory: evidence,
        enrichment: "",
        sshAudit: [],
      },
      attempt,
      client,
    )
  }
  return {
    name,
    offered,
    project,
    review,
    setUp,
    loads: () => loads,
    /** Park the next `count` prompts until release(), so their reviews overlap. */
    hold(count: number) {
      let ready!: () => void
      let open!: () => void
      const arrived = new Promise<void>((resolve) => (ready = resolve))
      held = { count, arrived: 0, ready, gate: new Promise<void>((resolve) => (open = resolve)) }
      release = () => {
        held = undefined
        open()
      }
      return {
        release,
        /** A review that ends before every prompt arrived never overlapped the others. */
        overlapped: (reviews: Array<Promise<unknown>>) =>
          Promise.race([
            arrived,
            ...reviews.map((review) =>
              review.then((result) => {
                throw new Error(`A review ended before ${count} prompts overlapped: ${JSON.stringify(result)}`)
              }),
            ),
          ]),
      }
    },
    async close(projects: Array<ReturnType<typeof project>>) {
      release?.()
      for (const attempt of attempts) attempt.close("cancelled")
      for (const { backend } of projects) await backend.dispose()
      await hostCleanup?.()
    },
  }
}

test("projects keep concurrent reviews isolated across a reload and backend disposal", async () => {
  const base = mkdtempSync(join(tmpdir(), "prb-shared-"))
  const previous = process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
  process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = base
  const host = sharedIsolationHost()
  const { review } = host
  const first = host.project("/workspace/first")
  const second = host.project("/workspace/second")
  try {
    expect((await review(first))).toMatchObject({ kind: "allow" })
    // A second project's first review binds its hooks to the same instance.
    expect((await review(second))).toMatchObject({ kind: "allow" })
    expect((await review(first))).toMatchObject({ kind: "allow" })
    const overlap = host.hold(16)
    const concurrent = Array.from({ length: 16 }, (_, index) =>
      review(index % 2 === 0 ? first : second),
    )
    await overlap.overlapped(concurrent)
    // Reload while both projects have eight in-flight reviews. New hooks must
    // route each session's own prompt and decision after the old hooks go away.
    await host.setUp(base)
    overlap.release()
    for (const result of await Promise.all(concurrent)) expect(result).toMatchObject({ kind: "allow" })
    expect((await review(first))).toMatchObject({ kind: "allow" })
    expect((await review(second))).toMatchObject({ kind: "allow" })
    await first.backend.dispose()
    expect((await review(second))).toMatchObject({ kind: "allow" })
    expect(host.offered).toEqual(Array.from({ length: 22 }, () => [host.name]))
  } finally {
    await host.close([first, second])
    if (previous === undefined) delete process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
    else process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = previous
    await rm(base, { recursive: true, force: true })
    await rm(`${base}.owner`, { force: true })
  }
})

test("projects whose first reviews start together share one prepared isolation folder", async () => {
  const base = mkdtempSync(join(tmpdir(), "prb-shared-cold-"))
  const previous = process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
  process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = base
  const host = sharedIsolationHost()
  const projects = Array.from({ length: 4 }, (_, index) => host.project(`/workspace/cold-${index}`))
  try {
    // Every backend prepares the folder for its first review, as when the app opens several sessions.
    const overlap = host.hold(8)
    const reviews = projects.flatMap((project) => [host.review(project), host.review(project)])
    await overlap.overlapped(reviews)
    overlap.release()
    for (const result of await Promise.all(reviews)) expect(result).toMatchObject({ kind: "allow" })
    expect(host.loads()).toBe(1)
    expect((await readdir(base)).sort()).toEqual(["index.js", "opencode.json", "package.json"])
    expect(host.offered).toEqual(Array.from({ length: 8 }, () => [host.name]))
  } finally {
    await host.close(projects)
    if (previous === undefined) delete process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
    else process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = previous
    await rm(base, { recursive: true, force: true })
    await rm(`${base}.owner`, { force: true })
  }
})

test("a host instance set up before the last one is disposed still gets its own hooks", async () => {
  const base = mkdtempSync(join(tmpdir(), "prb-reload-"))
  const previous = process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
  process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = base
  const bound: unknown[] = []
  let disposed = 0
  const location = await createIsolatedLocation(async (ctx) => {
    bound.push(ctx)
    return async () => void disposed++
  })
  try {
    const plugin = await import(pathToFileURL(join(location.directory, "index.js")).href)
    const instance = () => ({
      location: { directory: location.directory },
      mcp: {
        transform: async (
          callback: (editor: { list(): []; remove(name: string): void }) => void,
        ) => {
          await callback({ list: () => [], remove: () => {} })
          return async () => {}
        },
      },
    })
    const first = instance()
    const second = instance()
    const disposeFirst = await plugin.default.setup(first)
    await plugin.default.setup(first)
    expect(bound).toHaveLength(1)
    const disposeSecond = await plugin.default.setup(second)
    expect(bound).toHaveLength(2)
    expect(bound[0]).toBe(first)
    expect(bound[1]).toBe(second)
    await disposeFirst()
    await disposeFirst()
    expect(disposed).toBe(1)
    await disposeSecond()
    expect(disposed).toBe(2)
  } finally {
    location.release()
    if (previous === undefined) delete process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
    else process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = previous
    await rm(base, { recursive: true, force: true })
    await rm(`${base}.owner`, { force: true })
  }
})
