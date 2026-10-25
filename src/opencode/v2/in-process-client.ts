import { resolve } from "node:path"
import type { OpenCodeClient } from "@opencode/client"
import type { Plugin } from "@opencode/plugin"

type Context = Parameters<Plugin.Plugin["setup"]>[0]

/** Plugin, model, and session calls are bound to the context that owns them. */
export interface IsolationQueryContext {
  readonly location?: { readonly directory?: string }
  plugin: {
    list(
      input?: { location?: { directory?: string } },
      options?: { signal?: AbortSignal },
    ): Promise<{ location?: { directory?: string }; data: unknown[] }>
  }
  model: {
    list(
      input?: { location?: { directory?: string } },
      options?: { signal?: AbortSignal },
    ): Promise<{ location?: { directory?: string }; data: unknown[] }>
  }
  /** Present once the isolation plugin is the context that owns the directory. */
  session?: object
}

const isolationContexts = new Map<string, IsolationQueryContext>()

function locationKey(directory: string): string {
  const resolved = resolve(directory)
  return process.platform === "win32" ? resolved.toLowerCase() : resolved
}

/** Remember the context the host passed into an isolation plugin setup. */
export function noteIsolationContext(directory: string, ctx: IsolationQueryContext): void {
  isolationContexts.set(locationKey(directory), ctx)
  const reported = ctx.location?.directory
  if (reported) isolationContexts.set(locationKey(reported), ctx)
}

/** Drop that context when the isolation location is released. */
export function forgetIsolationContext(directory: string): void {
  const current = isolationContexts.get(locationKey(directory))
  if (!current) {
    isolationContexts.delete(locationKey(directory))
    return
  }
  for (const [key, ctx] of isolationContexts) {
    if (ctx === current) isolationContexts.delete(key)
  }
}

function method<A extends unknown[], R>(owner: object, name: string): (...args: A) => R {
  const fn = (owner as Record<string, unknown>)[name]
  if (typeof fn !== "function") {
    return () => {
      throw new Error(`Reviewer in-process host cannot ${name}`)
    }
  }
  return fn.bind(owner) as (...args: A) => R
}

function assertInventoryLocation(
  kind: "plugin" | "model",
  directory: string,
  location: { directory?: string } | undefined,
): void {
  if (!location?.directory || locationKey(location.directory) !== locationKey(directory)) {
    throw new Error(
      kind === "plugin"
        ? "Reviewer plugin inventory belongs to another location"
        : "Reviewer model catalog belongs to another location",
    )
  }
}

/**
 * Review through the plugin context this process already has.
 *
 * `mcp.list` and `session.create` accept another directory. A session created
 * there belongs to that location, so prompt, wait, and cleanup run on the
 * isolation plugin context. `plugin.list` and `model.list` do too, after that
 * plugin activates. The HTTP identity check is not used here.
 */
export function createInProcessReviewClient(host: Context): OpenCodeClient {
  const ownedSessions = new Map<string, string>()
  const listPlugins = async (
    input?: { location?: { directory?: string } },
    options?: { signal?: AbortSignal },
  ) => {
    const directory = input?.location?.directory
    if (!directory) throw new Error("Reviewer isolation location is required")
    // Boot the other location, then read plugins from its own context. The
    // boot inventory is not a plugin list, and this host's plugin.list cannot
    // see that directory.
    let isolated = isolationContexts.get(locationKey(directory))
    if (!isolated) {
      await host.mcp.list({ location: { directory } }, options)
      isolated = isolationContexts.get(locationKey(directory))
    }
    if (!isolated) return { location: { directory }, data: [] }
    if (typeof isolated.plugin?.list !== "function")
      throw new Error("Reviewer isolation plugin context is incomplete")
    const listed = await isolated.plugin.list(undefined, options)
    assertInventoryLocation("plugin", directory, listed?.location)
    if (!Array.isArray(listed.data)) throw new Error("Reviewer plugin inventory is unavailable")
    return listed
  }
  const listModels = async (
    input?: { location?: { directory?: string } },
    options?: { signal?: AbortSignal },
  ) => {
    const directory = input?.location?.directory
    if (!directory) throw new Error("Reviewer isolation location is required")
    const isolated = isolationContexts.get(locationKey(directory))
    if (!isolated || typeof isolated.model?.list !== "function")
      throw new Error("Reviewer isolation plugin is not active")
    const listed = await isolated.model.list(undefined, options)
    assertInventoryLocation("model", directory, listed?.location)
    if (!Array.isArray(listed.data)) throw new Error("Reviewer model catalog is unavailable")
    return listed
  }
  const sessionTarget = (name: string, sessionID: unknown): object => {
    if (typeof sessionID !== "string") return host.session
    const directory = ownedSessions.get(sessionID)
    const isolated = directory
      ? (isolationContexts.get(locationKey(directory))?.session as
          Record<string, unknown> | undefined)
      : undefined
    if (!isolated || typeof isolated[name] !== "function") return host.session
    return isolated
  }
  const sessionCall = (name: string) => {
    return (...args: unknown[]) => {
      const input = args[0] as { sessionID?: unknown } | undefined
      return method(sessionTarget(name, input?.sessionID), name)(...args)
    }
  }
  const createSession = method<unknown[], { id?: unknown; location?: { directory?: unknown } }>(
    host.session,
    "create",
  )
  return {
    mcp: {
      list: method(host.mcp, "list"),
    },
    plugin: {
      list: listPlugins,
    },
    model: {
      list: listModels,
    },
    session: {
      create: async (...args: unknown[]) => {
        const created = await createSession(...args)
        const input = args[0] as { location?: { directory?: unknown } } | undefined
        const directory = created?.location?.directory ?? input?.location?.directory
        if (typeof created?.id === "string" && typeof directory === "string") {
          if (ownedSessions.size >= 256) ownedSessions.delete(ownedSessions.keys().next().value!)
          ownedSessions.set(created.id, directory)
        }
        return created
      },
      get: sessionCall("get"),
      context: sessionCall("context"),
      prompt: sessionCall("prompt"),
      wait: sessionCall("wait"),
      interrupt: sessionCall("interrupt"),
      remove: sessionCall("remove"),
    },
  } as unknown as OpenCodeClient
}
