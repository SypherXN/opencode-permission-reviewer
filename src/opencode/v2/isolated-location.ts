import { chmod, lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises"
import { dirname, join } from "node:path"
import type { Plugin } from "@opencode/plugin"
import { expandHome } from "../../audit.ts"
import {
  forgetIsolationContext,
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
  const directory = await claim(
    expandHome(process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR ?? DEFAULT_DIRECTORY),
  )
  // Older builds recorded the owner inside the trusted folder. One removal, then it stays gone.
  await rm(join(directory, "owner.pid"), { force: true })
  const key = ACTIVATION
  const pluginID = PLUGIN_ID
  let current: (() => Promise<void>) | undefined
  const activation: Activate = async (ctx) => {
    if (!sameIsolationDirectory(ctx.location.directory, directory))
      throw new Error("Reviewer isolation location mismatch")
    // plugin.list and model.list on the host context cannot see this directory.
    noteIsolationContext(directory, ctx)
    // The host can call setup again after it disposes the previous hooks.
    // A second call while those hooks are still live must not register them twice.
    if (current) return async () => {}
    const cleanup = await activate(ctx)
    const dispose = async () => {
      if (current !== dispose) return
      current = undefined
      await cleanup()
    }
    current = dispose
    return dispose
  }
  activations.set(key, activation)
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
      // Keep the explicit reviewer model unchanged by inherited QM agent hooks.
      JSON.stringify({ plugins: ["-opencode.config.mcp", "-quartermaster", directory] }),
    )
    await bindPublishedContext(directory, activation)
    return {
      directory,
      pluginID,
      release: () => {
        // The directory stays: it is what the host was asked to trust.
        if (activations.get(key) === activation) activations.delete(key)
        forgetIsolationContext(directory)
      },
    }
  } catch (error) {
    if (activations.get(key) === activation) activations.delete(key)
    forgetIsolationContext(directory)
    throw error
  }
}
