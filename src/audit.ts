import type { Database } from "bun:sqlite"
import { mkdir } from "node:fs/promises"
import { createRequire } from "node:module"
import {
  closeSync,
  constants as fsConstants,
  fchmodSync,
  fstatSync,
  ftruncateSync,
  lstatSync,
  openSync,
  readSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs"
import { homedir } from "node:os"
import { dirname, resolve } from "node:path"
import type { ReviewAuditRecord, ReviewerConfig } from "./types.ts"
import { redactSecrets } from "./redact.ts"

export const DEFAULT_AUDIT_PATH = "~/.local/share/opencode/permission-reviewer-audit.jsonl"

const O_RDONLY = typeof fsConstants.O_RDONLY === "number" ? fsConstants.O_RDONLY : 0
const O_WRONLY = typeof fsConstants.O_WRONLY === "number" ? fsConstants.O_WRONLY : 0
const O_CREAT = typeof fsConstants.O_CREAT === "number" ? fsConstants.O_CREAT : 0
const O_EXCL = typeof fsConstants.O_EXCL === "number" ? fsConstants.O_EXCL : 0
const O_APPEND = typeof fsConstants.O_APPEND === "number" ? fsConstants.O_APPEND : 0
const O_NOFOLLOW = typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0
const O_NONBLOCK = typeof fsConstants.O_NONBLOCK === "number" ? fsConstants.O_NONBLOCK : 0

export function expandHome(path: string): string {
  if (path === "~") return homedir()
  if (path.startsWith("~/")) return resolve(homedir(), path.slice(2))
  return resolve(path)
}

/** Resolve the audit path the way the writer does. */
export function resolveAuditPath(config: ReviewerConfig): string {
  return expandHome(config.auditPath ?? DEFAULT_AUDIT_PATH)
}

/** The required identity/decision fields every audit record must carry. Used
 *  by the report reader to flag truncated or malformed lines. */
const REQUIRED_AUDIT_FIELDS = [
  "timestamp",
  "requestID",
  "sessionID",
  "permission",
  "outcome",
  "reason",
] as const

export interface AuditMissingFields {
  lineNo: number
  missing: string[]
}

export interface AuditSummary {
  path: string
  exists: boolean
  /** True when only the bounded tail (most recent 64 MiB) was summarized:
   *  line counts and timestamps then describe that window, not the file. */
  truncated: boolean
  totalLines: number
  validRecords: number
  invalidLines: number
  bySchemaVersion: Record<string, number>
  byHostGeneration: Record<string, number>
  byApplication: Record<string, number>
  byOutcome: Record<string, number>
  byRiskLevel: Record<string, number>
  byDecisionSource: Record<string, number>
  byPermission: Record<string, number>
  unknownActorNames: Array<{ name: string; count: number }>
  missingRequiredFields: AuditMissingFields[]
  firstTimestamp?: string
  lastTimestamp?: string
}

function bump(map: Record<string, number>, key: string): void {
  map[key] = (map[key] ?? 0) + 1
}

/** Records older than this are removed by the next rewrite. Lines with no
 *  parseable timestamp stay, so a corrupt line is not treated as expired. The
 *  file is append-only between those rewrites. */
const AUDIT_RETENTION_MS = 24 * 60 * 60 * 1000

/** A rewrite starts only once the oldest record is this far past retention.
 *  Reviews arrive at a steady rate, so at the bare cutoff some record expires
 *  before nearly every append, and each append would copy the whole file. */
const AUDIT_PRUNE_SLACK_MS = 60 * 60 * 1000

/** Cap on how much of an audit file the summary reader will pull into memory.
 *  The writer drops expired records, and the report still only needs the most
 *  recent ones. When the cap is hit the reader summarizes the tail (newest
 *  records) and flags the truncation. */
const AUDIT_READ_CAP_BYTES = 64 * 1024 * 1024

/** Read the (bounded) tail of an audit file synchronously without loading the
 *  whole file. The size and the bytes both come from the open descriptor, so
 *  the window matches the data actually read. Never throws: any failure to
 *  open/stat/read returns undefined and the caller reports the file as
 *  unreadable. */
function readTail(path: string): { text: string; truncated: boolean } | undefined {
  let fd: number | undefined
  try {
    // Where O_NOFOLLOW is absent, lstat is what stops a symlink from being followed.
    try {
      const existing = lstatSync(path)
      if (existing.isSymbolicLink() || !existing.isFile()) return undefined
    } catch {
      return undefined
    }
    // O_NOFOLLOW rejects a symlinked audit path and O_NONBLOCK keeps a FIFO
    // from blocking the CLI before fstat can reject the non-regular file.
    fd = openSync(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW)
    const info = fstatSync(fd)
    if (!info.isFile()) return undefined
    const size = info.size
    const truncated = size > AUDIT_READ_CAP_BYTES
    const length = truncated ? AUDIT_READ_CAP_BYTES : size
    const buffer = Buffer.alloc(length)
    const offset = truncated ? size - length : 0
    // When the window does not start at the beginning of the file, its first
    // byte may land mid-line. Peek at the byte just before the window: a
    // newline there means the window already starts at a line boundary, so
    // the first line is whole and must be kept. Otherwise the first line may
    // be partial and is dropped below. A failed peek keeps the old
    // always-strip behavior; it only ever drops one line from the report.
    let atLineBoundary = false
    if (truncated && offset > 0) {
      try {
        const probe = Buffer.alloc(1)
        const seen = readSync(fd, probe, 0, 1, offset - 1)
        atLineBoundary = seen === 1 && probe[0] === 0x0a
      } catch {
        atLineBoundary = false
      }
    }
    let read = 0
    while (read < length) {
      const count = readSync(fd, buffer, read, length - read, offset + read)
      if (count === 0) break
      read += count
    }
    // A shrink after fstat can end the read early; decode only the bytes
    // actually read so no zero-padding leaks into the text.
    let text = (read < length ? buffer.subarray(0, read) : buffer).toString("utf8")
    if (truncated && !atLineBoundary) {
      // Drop a possibly partial first line so every summarized line is whole.
      text = text.replace(/^[^\n]*\n/, "")
    }
    return { text, truncated }
  } catch {
    return undefined
  } finally {
    if (fd !== undefined) closeSyncSafe(fd)
  }
}

function closeSyncSafe(fd: number): void {
  try {
    closeSync(fd)
  } catch {
    // Best effort; the read already succeeded or failed on its own.
  }
}

/** Read an append-only JSONL audit file and summarize it. Never throws: a
 *  missing/unreadable file returns an empty summary with `exists: false`, and
 *  malformed records (wrong shapes, null actors, bad JSON) are counted as
 *  invalid lines instead of aborting the report. */
export function readAuditSummary(path: string): AuditSummary {
  const summary: AuditSummary = {
    path,
    exists: false,
    truncated: false,
    totalLines: 0,
    validRecords: 0,
    invalidLines: 0,
    bySchemaVersion: {},
    byHostGeneration: {},
    byApplication: {},
    byOutcome: {},
    byRiskLevel: {},
    byDecisionSource: {},
    byPermission: {},
    unknownActorNames: [],
    missingRequiredFields: [],
  }
  const read = readTail(path)
  if (read === undefined) return summary
  summary.exists = true
  summary.truncated = read.truncated
  const lines = read.text.split("\n").filter((line) => line.trim().length > 0)
  // When the cap was hit only the tail was read; line counts then describe
  // the summarized window, not the whole file.
  summary.totalLines = lines.length
  const actorCounts = new Map<string, number>()
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1
    let parsed: unknown
    try {
      parsed = JSON.parse(lines[i]!)
    } catch {
      summary.invalidLines++
      continue
    }
    // A bare primitive or null/array is not an audit record; count it as an
    // invalid line instead of throwing on the property accesses below.
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      summary.invalidLines++
      continue
    }
    const record = parsed as Record<string, unknown>
    summary.validRecords++
    bump(summary.bySchemaVersion, String(record.schemaVersion ?? 1))
    bump(
      summary.byHostGeneration,
      record.hostGeneration === "v1" || record.hostGeneration === "v2"
        ? record.hostGeneration
        : "legacy-unspecified",
    )
    if (
      typeof record.application === "string" &&
      [
        "evaluation-returned",
        "reply-accepted",
        "human-pending",
        "superseded",
        "cancelled",
        "unknown",
      ].includes(record.application)
    )
      bump(summary.byApplication, record.application)
    if (typeof record.outcome === "string") bump(summary.byOutcome, record.outcome)
    bump(summary.byRiskLevel, typeof record.riskLevel === "string" ? record.riskLevel : "(none)")
    if (typeof record.decisionSource === "string")
      bump(summary.byDecisionSource, record.decisionSource)
    if (typeof record.permission === "string") bump(summary.byPermission, record.permission)
    if (typeof record.timestamp === "string") {
      if (summary.firstTimestamp === undefined || record.timestamp < summary.firstTimestamp) {
        summary.firstTimestamp = record.timestamp
      }
      if (summary.lastTimestamp === undefined || record.timestamp > summary.lastTimestamp) {
        summary.lastTimestamp = record.timestamp
      }
    }
    const missing = REQUIRED_AUDIT_FIELDS.filter((f) => record[f] === undefined)
    if (missing.length > 0) summary.missingRequiredFields.push({ lineNo, missing })
    const actor =
      typeof record.actor === "object" && record.actor !== null
        ? (record.actor as { name?: string; profile?: string })
        : undefined
    const isUnknown =
      actor === undefined ||
      actor.profile === undefined ||
      actor.profile === "unknown" ||
      actor.name === undefined ||
      actor.name === ""
    if (isUnknown) {
      const rawName = actor?.name ?? (record.actor === undefined ? "(no actor field)" : "(unnamed)")
      // A hostile or corrupted record can put anything in `name`; coerce to a
      // string before it reaches the localeCompare below.
      const name = typeof rawName === "string" ? rawName : JSON.stringify(rawName)
      actorCounts.set(name, (actorCounts.get(name) ?? 0) + 1)
    }
  }
  summary.unknownActorNames = [...actorCounts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
  return summary
}

function boundedReason(reason: string): string {
  const normalized = reason.replace(/[\r\n]+/g, " ").trim()
  return normalized.length <= 2_000 ? normalized : `${normalized.slice(0, 2_000)}…`
}

function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) return
  const code = (error as { code?: unknown }).code
  return typeof code === "string" ? code : undefined
}

type Sqlite = typeof import("bun:sqlite")
let sqlite: Sqlite | undefined

/** Loaded on first use, never at import: a host that runs plugins outside Bun
 *  must still load the reviewer, losing only its audit records. */
function loadSqlite(): Sqlite {
  sqlite ??= createRequire(import.meta.url)("bun:sqlite") as Sqlite
  return sqlite
}

/** SQLite supplies a kernel-backed cross-process mutex, not audit storage.
 *  Closing it (including process death) releases the lock. Never unlink this
 *  sidecar: replacing its inode would split the lock between live writers. */
function openAuditLock(path: string): Database {
  const lockPath = `${path}.lock.sqlite`
  for (const candidate of [path, lockPath]) {
    try {
      const info = lstatSync(candidate)
      if (info.isSymbolicLink() || !info.isFile() || info.nlink > 1) {
        throw new Error(`not a regular single-link file: ${candidate}`)
      }
    } catch (error) {
      if (errorCode(error) !== "ENOENT") throw error
    }
  }
  const { Database, constants } = loadSqlite()
  const db = new Database(
    lockPath,
    constants.SQLITE_OPEN_READWRITE | constants.SQLITE_OPEN_CREATE | constants.SQLITE_OPEN_NOFOLLOW,
  )
  try {
    // Wait asynchronously in the writer, never block the host on another process.
    db.run("PRAGMA busy_timeout = 0")
    db.run("BEGIN IMMEDIATE")
    return db
  } catch (error) {
    db.close()
    throw error
  }
}

async function waitForAuditLock(path: string): Promise<Database> {
  const deadline = Date.now() + 5_000
  for (;;) {
    try {
      return openAuditLock(path)
    } catch (error) {
      if (errorCode(error) !== "SQLITE_BUSY" || Date.now() >= deadline) throw error
      await new Promise((resolve) => setTimeout(resolve, 10))
    }
  }
}

/** Timestamp of one JSONL record, or undefined when the line is not a record. */
function recordTimestampMs(line: string): number | undefined {
  try {
    const parsed = JSON.parse(line) as { timestamp?: unknown }
    if (typeof parsed !== "object" || parsed === null || typeof parsed.timestamp !== "string") {
      return
    }
    const ms = Date.parse(parsed.timestamp)
    return Number.isFinite(ms) ? ms : undefined
  } catch {
    return
  }
}

function readAt(fd: number, offset: number, length: number): Buffer {
  const buffer = Buffer.alloc(length)
  let read = 0
  while (read < length) {
    const count = readSync(fd, buffer, read, length - read, offset + read)
    if (count === 0) break
    read += count
  }
  return read < length ? buffer.subarray(0, read) : buffer
}

/** True when the oldest dated record is past the cutoff, or none is found near
 *  the head. An append-only file is oldest-first, so a recent one needs no rewrite. */
function headNeedsPrune(fd: number, size: number, cutoff: number): boolean {
  const max = Math.min(size, 256 * 1024)
  let carry = Buffer.alloc(0)
  let offset = 0
  while (offset < max) {
    const slice = readAt(fd, offset, Math.min(8 * 1024, max - offset))
    if (slice.length === 0) break
    offset += slice.length
    const combined = carry.length === 0 ? slice : Buffer.concat([carry, slice])
    let start = 0
    for (let newline = combined.indexOf(0x0a); newline !== -1; newline = combined.indexOf(0x0a, start)) {
      const timestamp = recordTimestampMs(combined.subarray(start, newline).toString("utf8"))
      // A rewrite keeps blank and undated lines, so they cannot be why one is needed.
      if (timestamp !== undefined) return timestamp < cutoff
      start = newline + 1
    }
    carry = Buffer.from(combined.subarray(start))
  }
  return true
}

function writeFully(fd: number, data: Buffer, position?: number): void {
  let written = 0
  while (written < data.length) {
    const count = writeSync(
      fd,
      data,
      written,
      data.length - written,
      position === undefined ? undefined : position + written,
    )
    if (count === 0) throw new Error("short write")
    written += count
  }
}

/** Copy lines that are still inside the retention window. Expired records are
 *  counted and dropped. Blank lines are not records and are not copied. */
function writeRetainedLines(input: number, size: number, output: number, cutoff: number): number {
  let offset = 0
  let carry = Buffer.alloc(0)
  let dropped = 0
  const keep = (line: Buffer) => {
    if (line.length === 0) return
    const text = line.toString("utf8")
    const timestamp = recordTimestampMs(text)
    if (timestamp !== undefined && timestamp < cutoff) {
      dropped++
      return
    }
    writeFully(output, Buffer.concat([line, Buffer.from("\n")]))
  }
  while (offset < size) {
    const slice = readAt(input, offset, Math.min(64 * 1024, size - offset))
    if (slice.length === 0) break
    offset += slice.length
    const combined = carry.length === 0 ? slice : Buffer.concat([carry, slice])
    let start = 0
    for (let index = 0; index < combined.length; index++) {
      if (combined[index] !== 0x0a) continue
      keep(combined.subarray(start, index))
      start = index + 1
    }
    carry = Buffer.from(combined.subarray(start))
  }
  if (carry.length > 0) keep(carry)
  return dropped
}

function assertRegularFile(fd: number, path: string): void {
  if (!fstatSync(fd).isFile()) throw new Error(`not a regular file: ${path}`)
}

function enforceOwnerMode(fd: number): void {
  try {
    if ((fstatSync(fd).mode & 0o7777) !== 0o600) fchmodSync(fd, 0o600)
  } catch (error) {
    throw new Error(
      `cannot enforce mode 0600 on the audit path (chmod 600 it or fix its ownership): ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    )
  }
}

/** Open a new regular file. A symlink at this path is refused, never followed. */
function openFreshRegularFile(path: string): number {
  let existing: ReturnType<typeof lstatSync> | undefined
  try {
    existing = lstatSync(path)
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error
  }
  if (existing) {
    if (existing.isSymbolicLink() || !existing.isFile()) throw new Error(`not a regular file: ${path}`)
    unlinkSync(path)
  }
  const fd = openSync(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
  try {
    assertRegularFile(fd, path)
    enforceOwnerMode(fd)
    return fd
  } catch (error) {
    closeSyncSafe(fd)
    throw error
  }
}

function removeRegularFile(path: string): void {
  let existing: ReturnType<typeof lstatSync>
  try {
    existing = lstatSync(path)
  } catch (error) {
    if (errorCode(error) === "ENOENT") return
    throw error
  }
  if (existing.isSymbolicLink() || !existing.isFile()) throw new Error(`not a regular file: ${path}`)
  unlinkSync(path)
}

/** Replace the audit file with the temp file. A rename that cannot overwrite
 *  copies onto the original descriptor instead, still refusing a symlink. */
function replaceRegularFile(temp: string, path: string): void {
  try {
    renameSync(temp, path)
    return
  } catch (error) {
    const code = errorCode(error)
    if (code !== "EEXIST" && code !== "EPERM" && code !== "EBUSY") throw error
  }
  let source: number | undefined
  let target: number | undefined
  try {
    const existing = lstatSync(path)
    if (existing.isSymbolicLink() || !existing.isFile()) throw new Error(`not a regular file: ${path}`)
    source = openSync(temp, O_RDONLY | O_NONBLOCK | O_NOFOLLOW)
    assertRegularFile(source, temp)
    target = openSync(path, O_WRONLY | O_NOFOLLOW)
    assertRegularFile(target, path)
    enforceOwnerMode(target)
    let offset = 0
    for (;;) {
      const slice = readAt(source, offset, 64 * 1024)
      if (slice.length === 0) break
      writeFully(target, slice, offset)
      offset += slice.length
    }
    ftruncateSync(target, offset)
  } finally {
    if (source !== undefined) closeSyncSafe(source)
    if (target !== undefined) closeSyncSafe(target)
    removeRegularFile(temp)
  }
}

/** Drop records older than 24 hours once the oldest is an hour past that.
 *  Returns how many records were removed. Never follows a symlink. A missing
 *  file removes nothing. */
export function pruneExpiredAudit(path: string, now = Date.now()): number {
  try {
    const info = lstatSync(path)
    if (info.isSymbolicLink() || !info.isFile()) return 0
  } catch (error) {
    if (errorCode(error) === "ENOENT") return 0
    throw error
  }
  const lock = openAuditLock(path)
  try {
    return pruneAuditLocked(path, now)
  } finally {
    lock.close()
  }
}

/** Caller holds the same lock used by every append. */
function pruneAuditLocked(path: string, now: number): number {
  let input: number | undefined
  let output: number | undefined
  // Separate a crashed process's leftover rewrite from this process's temp file.
  const temp = `${path}.${process.pid}.tmp`
  let removeTemp = false
  try {
    try {
      const existing = lstatSync(path)
      if (existing.isSymbolicLink() || !existing.isFile()) return 0
    } catch (error) {
      if (errorCode(error) === "ENOENT") return 0
      throw error
    }
    input = openSync(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW)
    const info = fstatSync(input)
    if (!info.isFile() || info.size === 0) return 0
    const cutoff = now - AUDIT_RETENTION_MS
    if (!headNeedsPrune(input, info.size, cutoff - AUDIT_PRUNE_SLACK_MS)) return 0
    output = openFreshRegularFile(temp)
    removeTemp = true
    const dropped = writeRetainedLines(input, info.size, output, cutoff)
    closeSyncSafe(output)
    output = undefined
    closeSyncSafe(input)
    input = undefined
    if (dropped === 0) {
      removeRegularFile(temp)
      removeTemp = false
      return 0
    }
    replaceRegularFile(temp, path)
    removeTemp = false
    return dropped
  } finally {
    if (output !== undefined) closeSyncSafe(output)
    if (input !== undefined) closeSyncSafe(input)
    if (removeTemp) {
      try {
        removeRegularFile(temp)
      } catch {
        // The temp file is only an intermediate rewrite. Leaving a symlink
        // alone is safer than deleting whatever it points at.
      }
    }
  }
}

export function createAuditWriter(
  config: ReviewerConfig,
  logger?: (message: string, details?: unknown) => void,
): ((record: ReviewAuditRecord) => Promise<void>) | undefined {
  if (!config.audit) return
  const path = expandHome(config.auditPath ?? DEFAULT_AUDIT_PATH)
  let directoryReady: Promise<void> | undefined
  // Keep this writer's order; the SQLite lock also covers other writers/processes.
  let tail: Promise<void> = Promise.resolve()
  return async (record) => {
    const run = tail.then(async () => {
      try {
        directoryReady ??= mkdir(dirname(path), { recursive: true }).then(() => {})
        await directoryReady
      } catch (error) {
        // The audit trail is best-effort: a directory that cannot be created
        // loses the record the same way an append failure does, logged and
        // never thrown. The cached promise is cleared so a later record retries
        // the mkdir instead of sticking to the rejection.
        logger?.("failed to append audit record", {
          path,
          error: error instanceof Error ? error.message : String(error),
        })
        directoryReady = undefined
        return
      }
      // Redact the free-text fields (the reason carries transport error messages
      // and provider responses that never passed through the evidence
      // pipeline's redaction). Structural identifiers are left intact: running
      // the redactor over the whole serialized line would also match key names
      // like "sessionID" and corrupt the record's correlation fields.
      const sanitized: ReviewAuditRecord = {
        ...record,
        reason: redactSecrets(boundedReason(record.reason)),
        ...(record.warnings === undefined
          ? {}
          : { warnings: record.warnings.map((warning) => redactSecrets(warning)) }),
        ...(record.policyTrace === undefined
          ? {}
          : {
              policyTrace: {
                ...record.policyTrace,
                // Rule reasons are admin-authored prose; redact them like any
                // other free text without touching the structural fields.
                matchedRules: record.policyTrace.matchedRules.map((match) => ({
                  ...match,
                  reason: redactSecrets(match.reason),
                })),
              },
            }),
        ...(record.askDecisions === undefined
          ? {}
          : {
              askDecisions: record.askDecisions.map((decision) => ({
                ...decision,
                question: redactSecrets(decision.question),
                answer: redactSecrets(decision.answer),
              })),
            }),
        ...(record.reviewerEscalatedFrom === undefined
          ? {}
          : {
              reviewerEscalatedFrom: {
                ...record.reviewerEscalatedFrom,
                reason: redactSecrets(boundedReason(record.reviewerEscalatedFrom.reason)),
              },
            }),
      }
      try {
        const lock = await waitForAuditLock(path)
        try {
          try {
            const dropped = pruneAuditLocked(path, Date.now())
            if (dropped > 0) logger?.("pruned audit records older than 24 hours", { path, dropped })
          } catch (error) {
            // Retention failure must not discard this record. Still hold the lock.
            logger?.("failed to prune audit records", {
              path,
              error: error instanceof Error ? error.message : String(error),
            })
          }
          appendAuditLine(path, `${JSON.stringify(sanitized)}\n`)
        } finally {
          lock.close()
        }
      } catch (error) {
        // The audit trail is best-effort: a lost record is logged, never thrown.
        logger?.("failed to append audit record", {
          path,
          error: error instanceof Error ? error.message : String(error),
        })
      }
    })
    tail = run.then(
      () => undefined,
      () => undefined,
    )
    await run
  }
}

/** Append one JSONL line through an explicitly opened descriptor: O_NOFOLLOW
 *  rejects a symlinked audit path, O_NONBLOCK refuses to hang on a FIFO
 *  destination (a write-open on a readerless FIFO fails with ENXIO instead of
 *  blocking the host forever), the descriptor is verified to be a regular
 *  file before writing, and mode 0600 is asserted on every append — a
 *  pre-existing group- or world-readable audit file is tightened before it
 *  receives new records, matching the documented 0600 guarantee instead of
 *  silently extending a looser mode. If the mode cannot be enforced (for
 *  example a file owned by another user), the append fails rather than adding
 *  records to a readable file. One open per record matches the previous
 *  append-per-call behavior. Throws on failure; the caller logs and swallows. */
function appendAuditLine(path: string, line: string): void {
  let fd: number | undefined
  try {
    try {
      const existing = lstatSync(path)
      if (existing.isSymbolicLink() || !existing.isFile()) {
        throw new Error(`not a regular file: ${path}`)
      }
    } catch (error) {
      if ((error as { code?: unknown }).code !== "ENOENT") throw error
    }
    // One atomic open covers creation and append without a path check or retry.
    // The creation mode closes the umask window before the first record.
    fd = openSync(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK, 0o600)
    const info = fstatSync(fd)
    if (!info.isFile()) {
      throw new Error(`not a regular file: ${path}`)
    }
    try {
      // 0o7777 so setuid/setgid residue also counts as wrong.
      if ((info.mode & 0o7777) !== 0o600) fchmodSync(fd, 0o600)
    } catch (error) {
      throw new Error(
        `cannot enforce mode 0600 on the audit path (chmod 600 it or fix its ownership): ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error },
      )
    }
    const data = Buffer.from(line, "utf8")
    let written = 0
    while (written < data.length) {
      const count = writeSync(fd, data, written, data.length - written)
      written += count
    }
  } finally {
    if (fd !== undefined) closeSyncSafe(fd)
  }
}
