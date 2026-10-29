import { chmod, lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises"
import { dirname, join } from "node:path"
import type { Plugin } from "@opencode/plugin"
import { expandHome } from "../../audit.ts"
import {
  forgetIsolationContext,
  locationKey,
  noteIsolationContext,
  sameIsolationDirectory,
} from "./in-process-client.ts"

type Context = Parameters<Plugin.Plugin["setup"]>[0]
type Activate = (ctx: Context) => Promise<() => Promise<void>>
const KEY = "opencode-permission-reviewer.isolated-activation"
const symbol = Symbol.for(KEY)
const globals = globalThis as typeof globalThis & { [symbol]: Map<string, Activate> | undefined }
const activations = globals[symbol] ?? new Map<string, Activate>()
globals[symbol] = activations
const MEMBERS_KEY = "opencode-permission-reviewer.isolated-members"
const membersSymbol = Symbol.for(MEMBERS_KEY)
const memberGlobals = globalThis as typeof globalThis & {
  [membersSymbol]: Map<Activate, string> | undefined
}
/** Each live claim's activation and folder. Every project's backend claims the same folder. */
const members = memberGlobals[membersSymbol] ?? new Map<Activate, string>()
memberGlobals[membersSymbol] = members

const preparationSymbol = Symbol.for("opencode-permission-reviewer.isolated-preparations")
const preparationGlobals = globalThis as typeof globalThis & {
  [preparationSymbol]: Map<string, Promise<void>> | undefined
}
// Share only file preparation across plugin instances, never hook activation or reviews.
const preparations = preparationGlobals[preparationSymbol] ?? new Map<string, Promise<void>>()
preparationGlobals[preparationSymbol] = preparations

/**
 * The host sets up a new instance of the folder after a reload. Each live
 * backend needs its hooks on that instance, not only the one that claimed the
 * folder last, or its reviews run without the decision tool.
 */
async function activateAll(ctx: Context): Promise<() => Promise<void>> {
  const claims = [...members]
    .filter(([, directory]) => sameIsolationDirectory(ctx.location.directory, directory))
    .map(([activate]) => activate)
  const results = await Promise.allSettled(claims.map((activate) => activate(ctx)))
  const cleanups = results.flatMap((result) => (result.status === "fulfilled" ? [result.value] : []))
  const dispose = async () => {
    const settled = await Promise.allSettled(cleanups.map((cleanup) => cleanup()))
    const failed = settled.find((result) => result.status === "rejected")
    if (failed) throw failed.reason
  }
  const failed = results.find((result) => result.status === "rejected")
  if (failed) {
    await dispose().catch(() => {})
    throw failed.reason
  }
  return dispose
}

/**
 * A host asks once per folder whether to run its code and answers again only
 * when the folder's files change. One directory that outlives a review keeps
 * that answer; a fresh temporary directory per review asks every time.
 */
const DEFAULT_DIRECTORY = "~/.local/share/opencode/permission-reviewer-isolation"

/**
 * A host may cache the bootstrap module for a path it already loaded, so the
 * key cannot change per review; a stale module must still find the activation.
 */
const ACTIVATION = "isolation"
const PLUGIN_ID = "permission-reviewer-isolation"
/**
 * The host calls setup once per process. The plugin stores that context here
 * so a later review can bind it without changing the trusted files.
 */
const CONTEXT_KEY = "opencode-permission-reviewer.isolated-contexts"
const contextSymbol = Symbol.for(CONTEXT_KEY)
const contextGlobals = globalThis as typeof globalThis & {
  [contextSymbol]: Map<string, Context> | undefined
}

function publishedContexts(): Map<string, Context> {
  const existing = contextGlobals[contextSymbol]
  if (existing) return existing
  const created = new Map<string, Context>()
  contextGlobals[contextSymbol] = created
  return created
}

/** The lock sits beside the directory. A pid file inside it changes every start. */
function ownerLock(base: string): string {
  return `${base}.owner`
}

/** A mode change rewrites directory metadata, so only fix a directory that is wrong. */
async function prepareDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 })
  const info = await lstat(directory)
  // lstat, not stat: a symlink would send the reviewer's config somewhere else.
  if (!info.isDirectory()) throw new Error("Reviewer isolation path is not a directory")
  const mode = info.mode & 0o777
  // Windows reports a fixed mode, and chmod updates the directory timestamp.
  if (process.platform === "win32" ? (mode & 0o200) === 0 : mode !== 0o700)
    await chmod(directory, 0o700)
}

/**
 * Every host shares one trusted folder. The bootstrap bytes are stable, so a
 * second process must not mint a new directory and wait for a trust answer.
 * The lock records who last claimed it and stays outside the folder.
 */
async function claim(base: string): Promise<string> {
  await mkdir(dirname(base), { recursive: true, mode: 0o700 })
  await prepareDirectory(base)
  await writeIfChanged(ownerLock(base), `${process.pid}\n`)
  return base
}

/** Leave a byte-identical file alone so its timestamp stays part of a trusted folder. */
async function writeIfChanged(path: string, content: string): Promise<void> {
  const existing = await lstat(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return undefined
    throw error
  })
  if (existing && (!existing.isFile() || existing.nlink > 1))
    throw new Error("Reviewer isolation file is linked or not a regular file")
  if (existing && (await readFile(path, "utf8")) === content) return
  const temporary = `${path}.${process.pid}.tmp`
  try {
    await writeFile(temporary, content, { mode: 0o600 })
    await rename(temporary, path)
  } catch (error) {
    await rm(temporary, { force: true })
    throw error
  }
}

/** Attach hooks when this process already received the isolation plugin setup. */
async function bindPublishedContext(directory: string, activation: Activate): Promise<void> {
  for (const [published, ctx] of publishedContexts()) {
    if (!sameIsolationDirectory(published, directory)) continue
    await activation(ctx)
    return
  }
}

/** A host-loaded bootstrap registers only this backend's isolated hooks. */
export async function createIsolatedLocation(
  activate: Activate,
): Promise<{ directory: string; pluginID: string; release(): void }> {
  const directory = expandHome(
    process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR ?? DEFAULT_DIRECTORY,
  )
  const key = ACTIVATION
  const pluginID = PLUGIN_ID
  // Hooks belong to the host instance that set them up. A reload can set up the
  // next instance before it disposes the last, and that one must still get hooks.
  const live = new Set<Context>()
  const activation: Activate = async (ctx) => {
    if (!sameIsolationDirectory(ctx.location.directory, directory))
      throw new Error("Reviewer isolation location mismatch")
    // plugin.list and model.list on the host context cannot see this directory.
    noteIsolationContext(directory, ctx)
    // A repeated setup for an instance whose hooks are still live must not register them twice.
    if (live.has(ctx)) return async () => {}
    live.add(ctx)
    let cleanup: () => Promise<void>
    try {
      cleanup = await activate(ctx)
    } catch (error) {
      live.delete(ctx)
      throw error
    }
    let disposed = false
    return async () => {
      if (disposed) return
      disposed = true
      live.delete(ctx)
      await cleanup()
    }
  }
  members.set(activation, directory)
  activations.set(key, (ctx) => activateAll(ctx))
  const leave = () => {
    members.delete(activation)
    if ([...members.values()].some((claimed) => sameIsolationDirectory(claimed, directory))) return
    forgetIsolationContext(directory)
    if (members.size === 0) activations.delete(key)
  }
  // The local config only disables the config MCP loader, so servers that other plugins add
  // from code still reach this location. Global plugins set up before this one, so this
  // transform removes their servers, and a server added later fails the inventory check.
  // It registers before the activation lookup, so a reload after release() stays MCP-free.
  const source = `export default { id: ${JSON.stringify(pluginID)}, async setup(ctx) {
    await ctx.mcp.transform((editor) => {
      for (const [name] of editor.list()) editor.remove(name);
    });
    const directory = ctx.location?.directory;
    const contexts = globalThis[Symbol.for(${JSON.stringify(CONTEXT_KEY)})] ?? new Map();
    globalThis[Symbol.for(${JSON.stringify(CONTEXT_KEY)})] = contexts;
    if (directory) contexts.set(directory, ctx);
    const activate = globalThis[Symbol.for(${JSON.stringify(KEY)})]?.get(${JSON.stringify(key)});
    if (!activate) return async () => {};
    return activate(ctx);
  } };`
  try {
    const directoryKey = locationKey(directory)
    let preparing = preparations.get(directoryKey)
    if (!preparing) {
      preparing = (async () => {
        await claim(directory)
        // Older builds recorded the owner inside the trusted folder. One removal, then it stays gone.
        await rm(join(directory, "owner.pid"), { force: true })
        await writeIfChanged(join(directory, "index.js"), source)
        await writeIfChanged(
          join(directory, "package.json"),
          JSON.stringify({
            name: "permission-reviewer-isolation",
            private: true,
            type: "module",
            exports: "./index.js",
          }),
        )
        await writeIfChanged(
          join(directory, "opencode.json"),
          // Inherited QM hooks would change the model; opencode-usage would write here.
          JSON.stringify({
            plugins: ["-opencode.config.mcp", "-quartermaster", "-opencode-usage", directory],
          }),
        )
      })()
      preparations.set(directoryKey, preparing)
    }
    try {
      await preparing
    } finally {
      // Retry after either success or failure, without deleting a newer preparation.
      if (preparations.get(directoryKey) === preparing) preparations.delete(directoryKey)
    }
    await bindPublishedContext(directory, activation)
    return {
      directory,
      pluginID,
      // The directory stays: it is what the host was asked to trust.
      release: leave,
    }
  } catch (error) {
    leave()
    throw error
  }
}
