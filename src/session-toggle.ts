/*
 * Per-session OPR switch.
 *
 * `opr off` records a directory (every chat in it) and `opr off --session <id>`
 * records one session, in a small JSON file outside the workspace. The V2
 * permission gate reads that file fresh for each `ask` and, when the request is
 * covered, leaves it as `ask` for the human instead of calling the reviewer
 * model. It never turns anything into an approval.
 *
 * The file is user-owned state, not configuration: it is never read from a
 * project, and a missing, unreadable, malformed, or wrong-version file means
 * every session is on (fail safe).
 */
import { randomUUID } from "node:crypto"
import { lstatSync, readFileSync } from "node:fs"
import { mkdir, rename, rm, writeFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { expandHome } from "./audit.ts"

export const DEFAULT_SESSION_TOGGLE_PATH =
  "~/.local/share/opencode/permission-reviewer-sessions.json"

/** Test seam: never let tests touch the real file. */
export const SESSION_TOGGLE_PATH_ENV = "OPENCODE_PERMISSION_REVIEWER_SESSIONS_PATH"

const MAX_REASON_CHARS = 500

export interface SessionToggleEntry {
  reason?: string
  until?: string
}

export interface SessionToggleState {
  version: 1
  off: Record<string, SessionToggleEntry>
  /** Directory-scoped entries, keyed by `directoryKey`. */
  offDirectories: Record<string, SessionToggleEntry>
}

export interface SessionToggleStatus {
  disabled: boolean
  reason?: string
  until?: string
}

export function resolveSessionTogglePath(): string {
  return expandHome(process.env[SESSION_TOGGLE_PATH_ENV] ?? DEFAULT_SESSION_TOGGLE_PATH)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

/** A malformed entry is dropped, which reads as on. */
function parseEntry(value: unknown): SessionToggleEntry | undefined {
  if (!isRecord(value)) return
  if (value.until !== undefined && typeof value.until !== "string") return
  const reason =
    typeof value.reason === "string" && value.reason.trim().length > 0
      ? value.reason.trim()
      : undefined
  const until = typeof value.until === "string" ? value.until : undefined
  return { ...(reason === undefined ? {} : { reason }), ...(until === undefined ? {} : { until }) }
}

/** Cap on the state file. A larger file is not one this module wrote, so it is
 *  not read: every session stays on. */
const MAX_STATE_BYTES = 64 * 1024

/** Read the state file as a regular file of bounded size. A link or a special
 *  file (FIFO, device) can block or redirect a read that happens on the
 *  permission path, so neither is followed. */
function readStateSync(path: string): string | undefined {
  try {
    const info = lstatSync(path)
    if (!info.isFile() || info.size > MAX_STATE_BYTES) return
    return readFileSync(path, "utf8")
  } catch {
    return
  }
}

function parseEntries(value: unknown): Record<string, SessionToggleEntry> {
  // Null prototype so a sessionID like "constructor" cannot resolve to an
  // inherited value; Object.hasOwn is the second guard.
  const entries: Record<string, SessionToggleEntry> = Object.create(null)
  if (!isRecord(value)) return entries
  for (const [id, raw] of Object.entries(value)) {
    const entry = parseEntry(raw)
    if (entry !== undefined) entries[id] = entry
  }
  return entries
}

/** Read fresh state on every call. Any failure returns undefined: all on.
 *
 *  Synchronous on purpose: the permission hook calls this on its critical path,
 *  and an await here would yield before the review is registered, so a host
 *  event-stream loss or session interrupt during the read would be missed. */
export function readSessionToggle(
  path = resolveSessionTogglePath(),
): SessionToggleState | undefined {
  const raw = readStateSync(path)
  if (raw === undefined) return
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return
  }
  if (!isRecord(parsed) || parsed.version !== 1 || !isRecord(parsed.off)) return
  return {
    version: 1,
    off: parseEntries(parsed.off),
    offDirectories: parseEntries(parsed.offDirectories),
  }
}

/** Stable key for a directory: absolute, and case- and separator-insensitive
 *  on Windows so the CLI's cwd matches the path the host reports. */
export function directoryKey(directory: string): string {
  const absolute = resolve(directory)
  return process.platform === "win32"
    ? absolute.replace(/\\/g, "/").toLowerCase()
    : absolute
}

/** A lapsed or unparseable `until` counts as on. */
export function sessionToggleActive(entry: SessionToggleEntry, now = Date.now()): boolean {
  if (entry.until === undefined) return true
  const until = Date.parse(entry.until)
  return Number.isFinite(until) && until > now
}

function statusOf(entry: SessionToggleEntry | undefined, now: number): SessionToggleStatus {
  if (entry === undefined || !sessionToggleActive(entry, now)) return { disabled: false }
  return {
    disabled: true,
    ...(entry.reason === undefined ? {} : { reason: entry.reason }),
    ...(entry.until === undefined ? {} : { until: entry.until }),
  }
}

/** The review-gate decision for one session's own entry. */
export function sessionDisabled(
  sessionID: string,
  now = Date.now(),
  path = resolveSessionTogglePath(),
): SessionToggleStatus {
  const state = readSessionToggle(path)
  const entry = state !== undefined && Object.hasOwn(state.off, sessionID) ? state.off[sessionID] : undefined
  return statusOf(entry, now)
}

/** The review gate: a live entry for the session, or for its directory, means
 *  off. A lapsed entry is ignored and falls through to the next scope. */
export function oprDisabled(
  sessionID: string,
  directory?: string,
  now = Date.now(),
  path = resolveSessionTogglePath(),
): SessionToggleStatus {
  const state = readSessionToggle(path)
  if (state === undefined) return { disabled: false }
  if (Object.hasOwn(state.off, sessionID)) {
    const own = statusOf(state.off[sessionID], now)
    if (own.disabled) return own
  }
  if (directory === undefined) return { disabled: false }
  const key = directoryKey(directory)
  return Object.hasOwn(state.offDirectories, key)
    ? statusOf(state.offDirectories[key], now)
    : { disabled: false }
}

/** Temp file in the same directory plus rename: a reader never sees a partial
 *  file, and the 0600 mode is set before the rename publishes it. */
async function writeState(path: string, state: SessionToggleState): Promise<void> {
  await mkdir(dirname(path), { recursive: true })
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`
  try {
    await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 })
    await rename(temporary, path)
  } catch (error) {
    await rm(temporary, { force: true })
    throw error
  }
}

/** One line, bounded: the reason is user prose, not a secret cache. */
function entryFor(options: { reason?: string; minutes?: number; now?: number }): SessionToggleEntry {
  const now = options.now ?? Date.now()
  const reason = options.reason?.replace(/[\r\n]+/g, " ").trim().slice(0, MAX_REASON_CHARS)
  const until =
    options.minutes === undefined
      ? undefined
      : new Date(now + options.minutes * 60_000).toISOString()
  return { ...(reason ? { reason } : {}), ...(until === undefined ? {} : { until }) }
}

/** Read, apply, write. Only human-driven writers call this, so it takes no
 *  lock; a concurrent write can drop the other's change, not corrupt the file. */
async function mutate(path: string, change: (state: SessionToggleState) => void): Promise<void> {
  const state = readSessionToggle(path) ?? {
    version: 1 as const,
    off: Object.create(null) as Record<string, SessionToggleEntry>,
    offDirectories: Object.create(null) as Record<string, SessionToggleEntry>,
  }
  change(state)
  await writeState(path, state)
}

export async function setSessionOff(
  sessionID: string,
  options: { reason?: string; minutes?: number; now?: number } = {},
  path = resolveSessionTogglePath(),
): Promise<SessionToggleEntry> {
  const entry = entryFor(options)
  await mutate(path, (state) => {
    state.off[sessionID] = entry
  })
  return entry
}

/** Turns OPR off for every chat in the directory, including chats started later. */
export async function setDirectoryOff(
  directory: string,
  options: { reason?: string; minutes?: number; now?: number } = {},
  path = resolveSessionTogglePath(),
): Promise<SessionToggleEntry> {
  const entry = entryFor(options)
  const key = directoryKey(directory)
  await mutate(path, (state) => {
    state.offDirectories[key] = entry
  })
  return entry
}

/** Remove the entry. Returns false when the session was already on. */
export async function setSessionOn(
  sessionID: string,
  path = resolveSessionTogglePath(),
): Promise<boolean> {
  const state = readSessionToggle(path)
  if (state === undefined || !Object.hasOwn(state.off, sessionID)) return false
  delete state.off[sessionID]
  await writeState(path, state)
  return true
}

/** Remove the directory entry. Returns false when it was already on. */
export async function setDirectoryOn(
  directory: string,
  path = resolveSessionTogglePath(),
): Promise<boolean> {
  const state = readSessionToggle(path)
  const key = directoryKey(directory)
  if (state === undefined || !Object.hasOwn(state.offDirectories, key)) return false
  delete state.offDirectories[key]
  await writeState(path, state)
  return true
}
