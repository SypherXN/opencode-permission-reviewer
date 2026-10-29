import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { execFile as execFileCallback, spawn } from "node:child_process"
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises"
import { readFileSync, writeFileSync, openSync, writeSync, closeSync } from "node:fs"
import { join, dirname } from "node:path"
import { tmpdir } from "node:os"
import { pathToFileURL } from "node:url"
import { createAuditWriter, DEFAULT_AUDIT_PATH, pruneExpiredAudit, readAuditSummary } from "../src/audit.ts"
import { DEFAULT_CONFIG } from "../src/config.ts"
import type { ReviewAuditRecord } from "../src/types.ts"

const execFileAsync = (cmd: string, args: string[]) =>
  new Promise<void>((resolve, reject) => {
    execFileCallback(cmd, args, (error) => (error ? reject(error) : resolve()))
  })
const repoRoot = join(dirname(import.meta.path), "..")

function record(overrides: Partial<ReviewAuditRecord> = {}): ReviewAuditRecord {
  return {
    timestamp: new Date().toISOString(),
    durationMs: 42,
    requestID: "per_1",
    sessionID: "ses_main",
    permission: "bash",
    outcome: "allow",
    reason: "narrow safe command",
    ...overrides,
  }
}

/** Write a string at an absolute file offset, looping to completion. Lets
 *  tests plant small records at far offsets so the file grows sparsely. */
function writeAt(fd: number, data: string, position: number): void {
  const buffer = Buffer.from(data, "utf8")
  let written = 0
  while (written < buffer.length) {
    const count = writeSync(fd, buffer, written, buffer.length - written, position + written)
    if (count === 0) throw new Error("short write while building sparse fixture")
    written += count
  }
}

/** Node 22.18+ and 23.6+ run TypeScript sources directly; older Node cannot load them. */
function nodeWithTypeStripping(): string | undefined {
  const node = Bun.which("node")
  if (!node) return
  const [major = 0, minor = 0] = Bun.spawnSync([node, "--version"])
    .stdout.toString()
    .trim()
    .slice(1)
    .split(".")
    .map(Number)
  return major > 23 || (major === 23 && minor >= 6) || (major === 22 && minor >= 18) ? node : undefined
}
const node = nodeWithTypeStripping()

/** Real child processes, with bounded waits and output retained for failures. */
function auditChild(source: string, command: string[] = [process.execPath]) {
  const [executable = process.execPath, ...args] = command
  const child = spawn(executable, [...args, "-e", source], { stdio: ["ignore", "pipe", "pipe"] })
  let output = ""
  let errors = ""
  child.stdout.on("data", (chunk) => (output += chunk))
  child.stderr.on("data", (chunk) => (errors += chunk))
  const done = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL")
      reject(new Error(`audit child timed out: ${output}\n${errors}`))
    }, 10_000)
    child.on("error", (error) => {
      clearTimeout(timer)
      reject(error)
    })
    child.on("close", (code) => {
      clearTimeout(timer)
      if (code === 0) resolve()
      else reject(new Error(`audit child exited ${code}: ${output}\n${errors}`))
    })
  })
  void done.catch(() => {})
  return {
    done,
    output: () => output,
    async waitFor(text: string) {
      const deadline = Date.now() + 5_000
      while (!output.includes(text)) {
        if (Date.now() > deadline) throw new Error(`missing ${text}: ${output}\n${errors}`)
        await new Promise((resolve) => setTimeout(resolve, 10))
      }
    },
    async stop() {
      child.kill("SIGKILL")
      await done.catch(() => {})
    },
  }
}

describe("audit writer", () => {
  let directory: string

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "approval-reviewer-audit-"))
  })

  afterEach(async () => {
    await rm(directory, { recursive: true, force: true })
  })

  test("returns undefined when audit is disabled", () => {
    expect(createAuditWriter({ ...DEFAULT_CONFIG, audit: false })).toBeUndefined()
  })

  test("appends one JSONL line per record with mode 0600", async () => {
    const auditPath = join(directory, "audit.jsonl")
    const writeAudit = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath })!
    await writeAudit(record({ requestID: "per_a" }))
    await writeAudit(record({ requestID: "per_b" }))
    const content = await readFile(auditPath, "utf8")
    const lines = content.trim().split("\n")
    expect(lines).toHaveLength(2)
    expect(JSON.parse(lines[0]!).requestID).toBe("per_a")
    expect(JSON.parse(lines[1]!).requestID).toBe("per_b")
    const info = await stat(auditPath)
    if (process.platform !== "win32") expect(info.mode & 0o777).toBe(0o600)
  })

  test("lazily creates nested directories", async () => {
    const auditPath = join(directory, "nested", "deep", "audit.jsonl")
    const writeAudit = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath })!
    await writeAudit(record())
    const content = await readFile(auditPath, "utf8")
    expect(content.trim().length).toBeGreaterThan(0)
  })

  test("bounds CRLF/newlines to spaces and truncates to 2000 chars", async () => {
    const auditPath = join(directory, "audit.jsonl")
    const writeAudit = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath })!
    const longReason = `a\r\nb\nc${"x".repeat(3_000)}`
    await writeAudit(record({ reason: longReason }))
    const line = (await readFile(auditPath, "utf8")).trim()
    const parsed = JSON.parse(line) as ReviewAuditRecord
    expect(parsed.reason).not.toContain("\n")
    expect(parsed.reason).not.toContain("\r")
    expect(parsed.reason.length).toBeLessThanOrEqual(2_001) // 2000 + ellipsis
    expect(parsed.reason.endsWith("…")).toBe(true)
  })

  test("short reason is preserved (CRLF -> space normalization)", async () => {
    const auditPath = join(directory, "audit.jsonl")
    const writeAudit = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath })!
    await writeAudit(record({ reason: "line1\r\nline2\nline3" }))
    const line = (await readFile(auditPath, "utf8")).trim()
    const parsed = JSON.parse(line) as ReviewAuditRecord
    expect(parsed.reason).toBe("line1 line2 line3")
  })

  test("trims whitespace and preserves exact 2000 char boundary", async () => {
    const auditPath = join(directory, "audit.jsonl")
    const writeAudit = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath })!
    const exactly2000 = "a".repeat(2_000)
    await writeAudit(record({ reason: `  ${exactly2000}  ` }))
    const parsed = JSON.parse((await readFile(auditPath, "utf8")).trim()) as ReviewAuditRecord
    expect(parsed.reason).toBe(exactly2000)
    expect(parsed.reason.length).toBe(2_000)
  })

  test("logger is called on append failure but does not throw", async () => {
    // Use a directory path as auditPath so appendFile fails with EISDIR.
    await mkdir(join(directory, "dir-as-file"))
    const auditPath = join(directory, "dir-as-file")
    const logs: unknown[] = []
    const writeAudit = createAuditWriter(
      { ...DEFAULT_CONFIG, audit: true, auditPath },
      (_msg, details) => logs.push(details),
    )!
    await expect(writeAudit(record())).resolves.toBeUndefined()
    expect(logs.length).toBeGreaterThan(0)
  })

  test("a mkdir failure is logged and never thrown, and later records retry", async () => {
    // A regular file where a directory should be makes mkdir fail with
    // ENOTDIR, so the writer cannot reach the append path at all.
    const blocker = join(directory, "blocker")
    await writeFile(blocker, "x")
    const auditPath = join(blocker, "nested", "audit.jsonl")
    const details: unknown[] = []
    const writeAudit = createAuditWriter(
      { ...DEFAULT_CONFIG, audit: true, auditPath },
      (_msg, info) => details.push(info),
    )!
    await expect(writeAudit(record({ requestID: "per_lost_1" }))).resolves.toBeUndefined()
    // The failure is not sticky: every record logs, and the writer recovers
    // once the directory can be created.
    await expect(writeAudit(record({ requestID: "per_lost_2" }))).resolves.toBeUndefined()
    expect(details.length).toBeGreaterThanOrEqual(2)
    await rm(blocker, { force: true })
    await writeAudit(record({ requestID: "per_recovered" }))
    const parsed = JSON.parse((await readFile(auditPath, "utf8")).trim()) as ReviewAuditRecord
    expect(parsed.requestID).toBe("per_recovered")
  })

  test("a symlinked audit path is rejected without throwing and the target is untouched", async () => {
    const target = join(directory, "target.jsonl")
    await writeFile(target, "")
    await symlink(target, join(directory, "audit.jsonl"))
    const logs: unknown[] = []
    const writeAudit = createAuditWriter(
      { ...DEFAULT_CONFIG, audit: true, auditPath: join(directory, "audit.jsonl") },
      (_msg, details) => logs.push(details),
    )!
    await expect(writeAudit(record())).resolves.toBeUndefined()
    expect(logs.length).toBeGreaterThan(0)
    // The record is lost rather than written through the link.
    expect(await readFile(target, "utf8")).toBe("")
  })

  test("a non-regular audit path is rejected without throwing", async () => {
    // A character device opens fine but fails the regular-file check, the
    // same path a FIFO or socket takes after a successful non-blocking open.
    const logs: unknown[] = []
    const writeAudit = createAuditWriter(
      {
        ...DEFAULT_CONFIG,
        audit: true,
        // `NUL` resolves to a regular file named NUL. The device path stays a
        // character device through path.resolve, matching /dev/null.
        auditPath: process.platform === "win32" ? "\\\\.\\NUL" : "/dev/null",
      },
      (_msg, details) => logs.push(details),
    )!
    await expect(writeAudit(record())).resolves.toBeUndefined()
    expect(logs.length).toBeGreaterThan(0)
  })

  test("unsafe lock paths are refused without touching the audit log or link target", async () => {
    for (const kind of ["directory", "symlink", "hardlink"]) {
      const auditPath = join(directory, `${kind}.jsonl`)
      const lockPath = `${auditPath}.lock.sqlite`
      const target = join(directory, `${kind}-target`)
      const body = `${JSON.stringify(record({
        timestamp: new Date(Date.now() - 26 * 60 * 60 * 1000).toISOString(),
      }))}\n`
      await writeFile(auditPath, body)
      await writeFile(target, "keep-me")
      if (kind === "directory") await mkdir(lockPath)
      else if (kind === "symlink") await symlink(target, lockPath)
      else await link(target, lockPath)
      const logs: unknown[] = []
      const writer = createAuditWriter(
        { ...DEFAULT_CONFIG, audit: true, auditPath },
        (_message, details) => logs.push(details),
      )!
      await expect(writer(record())).resolves.toBeUndefined()
      expect(() => pruneExpiredAudit(auditPath)).toThrow("not a regular")
      expect(logs).toHaveLength(1)
      expect(await readFile(auditPath, "utf8")).toBe(body)
      expect(await readFile(target, "utf8")).toBe("keep-me")
    }
  })

  test("a readerless FIFO audit path fails fast instead of blocking the writer", async () => {
    // The dangerous shape is a FIFO at the audit path with no reader: a
    // blocking write-open would hang the host forever before the
    // regular-file check could run. The open is non-blocking, so the append
    // must fail (and be swallowed) promptly. Runs in a subprocess with its
    // own timeout: a regression to a blocking open shows up as the child
    // being killed, not as a hung test runner.
    const fifoPath = join(directory, "audit.jsonl")
    await execFileAsync("mkfifo", [fifoPath])
    const child = spawn(
      process.execPath,
      [
        "-e",
        `const { createAuditWriter } = await import(${JSON.stringify(join(repoRoot, "src/audit.ts"))})
const writer = createAuditWriter({
  ...(await import(${JSON.stringify(join(repoRoot, "src/config.ts"))})).DEFAULT_CONFIG,
  audit: true,
  auditPath: ${JSON.stringify(fifoPath)},
}, (_msg, details) => console.log(JSON.stringify(details)))
await writer({
  timestamp: new Date().toISOString(), durationMs: 1, requestID: "per_fifo",
  sessionID: "ses_main", permission: "bash", outcome: "allow", reason: "fifo probe",
})
console.log("DONE")`,
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    )
    let stdout = ""
    child.stdout.on("data", (chunk) => (stdout += chunk))
    const exitCode = await new Promise<number | null>((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL")
        reject(new Error("appendAuditLine blocked on the readerless FIFO"))
      }, 8_000)
      child.on("exit", (code) => {
        clearTimeout(timer)
        resolve(code)
      })
      child.on("error", reject)
    })
    expect(exitCode).toBe(0)
    expect(stdout).toContain("DONE")
  }, 30_000)

  test("a pre-existing group-readable audit file is tightened to 0600 on append", async () => {
    const auditPath = join(directory, "audit.jsonl")
    await writeFile(auditPath, "")
    await chmod(auditPath, 0o644)
    const writeAudit = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath })!
    await writeAudit(record({ requestID: "per_keep" }))
    const handle = await open(auditPath, "r")
    try {
      const info = await handle.stat()
      if (process.platform !== "win32") expect(info.mode & 0o777).toBe(0o600)
      const parsed = JSON.parse((await readFile(handle, "utf8")).trim()) as ReviewAuditRecord
      expect(parsed.requestID).toBe("per_keep")
    } finally {
      await handle.close()
    }
  })

  test("mode 0600 is re-asserted when the file is loosened between appends", async () => {
    const auditPath = join(directory, "audit-loosened.jsonl")
    const writeAudit = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath })!
    await writeAudit(record({ requestID: "loose_1" }))
    // An external process loosens the file mid-life.
    await chmod(auditPath, 0o644)
    await writeAudit(record({ requestID: "loose_2" }))
    const handle = await open(auditPath, "r")
    try {
      const info = await handle.stat()
      if (process.platform !== "win32") expect(info.mode & 0o777).toBe(0o600)
      const lines = (await readFile(handle, "utf8")).trim().split("\n")
      expect(lines).toHaveLength(2)
      expect((JSON.parse(lines[1]!) as ReviewAuditRecord).requestID).toBe("loose_2")
    } finally {
      await handle.close()
    }
  })

  test("expandHome handles ~ and ~/ paths without throwing", async () => {
    // We cannot write to real ~ in test, but we can verify that `~` and `~/...`
    // are resolved (not treated as relative) — by checking the writer is created
    // and that it does not synchronously throw. We do not actually write to ~.
    const writerTilde = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath: "~" })
    expect(writerTilde).toBeDefined()
    const writerHome = createAuditWriter({
      ...DEFAULT_CONFIG,
      audit: true,
      auditPath: "~/approval-reviewer-test-noop.jsonl",
    })
    expect(writerHome).toBeDefined()
    // Ensure DEFAULT_AUDIT_PATH uses ~ prefix convention.
    expect(DEFAULT_AUDIT_PATH.startsWith("~")).toBe(true)
  })

  test("concurrent writes are serialized via mkdir once", async () => {
    const auditPath = join(directory, "audit.jsonl")
    const writeAudit = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath })!
    await Promise.all([
      writeAudit(record({ requestID: "per_1" })),
      writeAudit(record({ requestID: "per_2" })),
      writeAudit(record({ requestID: "per_3" })),
    ])
    const lines = (await readFile(auditPath, "utf8")).trim().split("\n")
    expect(lines).toHaveLength(3)
    const ids = lines.map((l) => (JSON.parse(l) as ReviewAuditRecord).requestID).sort()
    expect(ids).toEqual(["per_1", "per_2", "per_3"])
  })

  test("pruning preserves another process's append and releases locks after a crash", async () => {
    for (const crash of [false, true]) {
      const auditPath = join(directory, `concurrent-${crash}.jsonl`)
      const gate = join(directory, `resume-${crash}`)
      const older = new Date(Date.now() - 26 * 60 * 60 * 1000).toISOString()
      await writeFile(auditPath, `${JSON.stringify(record({ requestID: "expired", timestamp: older }))}\n`)
      const setup = `
const { createAuditWriter } = await import(${JSON.stringify(join(repoRoot, "src/audit.ts"))});
const { DEFAULT_CONFIG } = await import(${JSON.stringify(join(repoRoot, "src/config.ts"))});
const writer = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath: ${JSON.stringify(auditPath)} },
  (message, details) => {
    if (message.startsWith("failed")) { console.error(message, details); process.exitCode = 1 }
  });`
      const pruning = auditChild(`
import { mock } from "bun:test";
import * as fs from "node:fs";
const rename = fs.renameSync;
mock.module("node:fs", () => ({ ...fs, renameSync(from, to) {
  if (to === ${JSON.stringify(auditPath)}) {
    console.log("PRUNING");
    const deadline = Date.now() + 8000;
    const wait = new Int32Array(new SharedArrayBuffer(4));
    while (!fs.existsSync(${JSON.stringify(gate)})) {
      if (Date.now() > deadline) throw new Error("pruning gate timed out");
      Atomics.wait(wait, 0, 0, 10);
    }
  }
  return rename(from, to);
} }));
${setup}
await writer(${JSON.stringify(record({ requestID: "pruner" }))});
console.log("DONE");`)
      let appending: ReturnType<typeof auditChild> | undefined
      try {
        await pruning.waitFor("PRUNING")
        appending = auditChild(`${setup}
console.log("WRITING");
await writer(${JSON.stringify(record({ requestID: "other-process" }))});
console.log("DONE");`)
        await appending.waitFor("WRITING")
        await new Promise((resolve) => setTimeout(resolve, 100))
        const waitedForPruner = !appending.output().includes("DONE")
        if (crash) await pruning.stop()
        else await writeFile(gate, "resume")
        await appending.done
        if (!crash) await pruning.done
        const ids = (await readFile(auditPath, "utf8")).trim().split("\n")
          .map((line) => (JSON.parse(line) as ReviewAuditRecord).requestID)
        expect(ids).toEqual(crash ? ["other-process"] : ["pruner", "other-process"])
        expect(waitedForPruner).toBe(true)
      } finally {
        await writeFile(gate, "resume")
        await pruning.stop()
        await appending?.stop()
      }
    }
  }, 30_000)

  test("independent writers and processes keep every record during a burst", async () => {
    const auditPath = join(directory, "burst.jsonl")
    const gate = join(directory, "start-burst")
    await writeFile(auditPath, `${JSON.stringify(record({
      requestID: "expired",
      timestamp: new Date(Date.now() - 26 * 60 * 60 * 1000).toISOString(),
    }))}\n`)
    const children = Array.from({ length: 4 }, (_, index) => auditChild(`
import { existsSync } from "node:fs";
const { createAuditWriter } = await import(${JSON.stringify(join(repoRoot, "src/audit.ts"))});
const { DEFAULT_CONFIG } = await import(${JSON.stringify(join(repoRoot, "src/config.ts"))});
const writer = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath: ${JSON.stringify(auditPath)} },
  (message, details) => {
    if (message.startsWith("failed")) { console.error(message, details); process.exitCode = 1 }
  });
console.log("READY");
while (!existsSync(${JSON.stringify(gate)})) await Bun.sleep(5);
for (let i = 0; i < 12; i++) {
  await writer({ ...${JSON.stringify(record())}, requestID: "child-${index}-" + i });
}`))
    try {
      await Promise.all(children.map((child) => child.waitFor("READY")))
      const local = Array.from({ length: 4 }, (_, index) => {
        const writer = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath })!
        return Promise.all(Array.from({ length: 12 }, (_, i) =>
          writer(record({ requestID: `local-${index}-${i}` })),
        ))
      })
      await writeFile(gate, "start")
      await Promise.all([...local, ...children.map((child) => child.done)])
      const ids = (await readFile(auditPath, "utf8")).trim().split("\n")
        .map((line) => (JSON.parse(line) as ReviewAuditRecord).requestID)
      const expected = ["child", "local"].flatMap((kind) =>
        Array.from({ length: 4 }, (_, index) =>
          Array.from({ length: 12 }, (_, i) => `${kind}-${index}-${i}`),
        ).flat(),
      )
      expect(ids.sort()).toEqual(expected.sort())
    } finally {
      await writeFile(gate, "start")
      await Promise.all(children.map((child) => child.stop()))
    }
  }, 20_000)

  test.skipIf(!node)("a runtime without bun:sqlite still loads the module and loses only the record", async () => {
    const auditPath = join(directory, "no-sqlite.jsonl")
    const child = auditChild(
      `
const { createAuditWriter } = await import(${JSON.stringify(pathToFileURL(join(repoRoot, "src/audit.ts")).href)});
const logs = [];
const writer = createAuditWriter({ audit: true, auditPath: ${JSON.stringify(auditPath)} },
  (message, details) => logs.push({ message, error: details?.error }));
await writer(${JSON.stringify(record())});
console.log(JSON.stringify(logs));`,
      [node!, "--input-type=module"],
    )
    await child.done
    expect(JSON.parse(child.output())).toEqual([
      { message: "failed to append audit record", error: expect.stringContaining("bun:sqlite") },
    ])
    await expect(stat(auditPath)).rejects.toThrow()
  })

  test("absolute non-tilde path is resolved", async () => {
    const auditPath = join(directory, "explicit.jsonl")
    const writeAudit = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath })!
    await writeAudit(record({ requestID: "per_x" }))
    const parsed = JSON.parse((await readFile(auditPath, "utf8")).trim()) as ReviewAuditRecord
    expect(parsed.requestID).toBe("per_x")
  })

  test("drops records older than 24 hours and keeps the recent ones", async () => {
    const auditPath = join(directory, "audit.jsonl")
    const hour = 60 * 60 * 1000
    // The oldest record must be an hour past retention before anything is rewritten.
    const older = new Date(Date.now() - 25 * hour - 60_000).toISOString()
    const expired = new Date(Date.now() - 24 * hour - 60_000).toISOString()
    const newer = new Date(Date.now() - 24 * hour + 60_000).toISOString()
    const lines = [
      JSON.stringify(record({ requestID: "per_old", timestamp: older })),
      JSON.stringify(record({ requestID: "per_old_in_slack", timestamp: expired })),
      "not json",
      JSON.stringify({ requestID: "per_undated", outcome: "allow" }),
      JSON.stringify(record({ requestID: "per_kept", timestamp: newer })),
    ]
    // A few hundred KiB crosses the rewrite's read chunks, including a line
    // that does not end on a chunk boundary.
    for (let index = 0; index < 800; index++) {
      lines.push(
        JSON.stringify(
          record({ requestID: `per_old_${index}`, timestamp: older, reason: "x".repeat(80) }),
        ),
      )
    }
    await writeFile(auditPath, `${lines.join("\n")}\n`)
    const writeAudit = createAuditWriter({ ...DEFAULT_CONFIG, audit: true, auditPath })!
    await writeAudit(record({ requestID: "per_new" }))
    const kept = (await readFile(auditPath, "utf8")).trim().split("\n")
    const ids = kept.map((line) => {
      try {
        return (JSON.parse(line) as { requestID?: string }).requestID ?? line
      } catch {
        return line
      }
    })
    expect(ids).toContain("per_kept")
    expect(ids).toContain("per_undated")
    expect(ids).toContain("not json")
    expect(ids).toContain("per_new")
    expect(ids.some((id) => id === "per_old" || id.startsWith("per_old_"))).toBe(false)
    await expect(stat(`${auditPath}.${process.pid}.tmp`)).rejects.toThrow()
  })

  test("no rewrite starts before the oldest record is an hour past retention", async () => {
    const auditPath = join(directory, "audit.jsonl")
    const hour = 60 * 60 * 1000
    const at = (age: number) =>
      JSON.stringify(
        record({ requestID: `per_${age}`, timestamp: new Date(Date.now() - age).toISOString() }),
      )
    // A rewrite opens this temp path, and a directory there makes that open throw.
    await mkdir(`${auditPath}.${process.pid}.tmp`)
    for (const head of [
      [at(24 * hour + 60_000)],
      // Undated lines survive a rewrite, so they must not trigger one either.
      ["not json", "", JSON.stringify({ requestID: "per_undated" }), at(hour)],
    ]) {
      await writeFile(auditPath, `${[...head, at(60_000)].join("\n")}\n`)
      expect(pruneExpiredAudit(auditPath)).toBe(0)
    }
    await writeFile(auditPath, `${[at(25 * hour + 60_000), at(60_000)].join("\n")}\n`)
    expect(() => pruneExpiredAudit(auditPath)).toThrow("not a regular file")
  })

  test("a symlinked audit file is not pruned through the link", async () => {
    const target = join(directory, "target.jsonl")
    const older = new Date(Date.now() - 26 * 60 * 60 * 1000).toISOString()
    await writeFile(target, `${JSON.stringify(record({ requestID: "per_old", timestamp: older }))}\n`)
    const link = join(directory, "audit.jsonl")
    await symlink(target, link)
    expect(pruneExpiredAudit(link)).toBe(0)
    expect(await readFile(target, "utf8")).toContain("per_old")
  })

  test("a symlinked rewrite temp is not followed", async () => {
    const auditPath = join(directory, "audit.jsonl")
    const secret = join(directory, "secret.jsonl")
    await writeFile(secret, "keep-me")
    await symlink(secret, `${auditPath}.${process.pid}.tmp`)
    const older = new Date(Date.now() - 26 * 60 * 60 * 1000).toISOString()
    await writeFile(auditPath, `${JSON.stringify(record({ requestID: "per_old", timestamp: older }))}\n`)
    const logs: unknown[] = []
    const writeAudit = createAuditWriter(
      { ...DEFAULT_CONFIG, audit: true, auditPath },
      (_message, details) => logs.push(details),
    )!
    await writeAudit(record({ requestID: "per_new" }))
    expect(await readFile(secret, "utf8")).toBe("keep-me")
    const body = await readFile(auditPath, "utf8")
    expect(body).toContain("per_old")
    expect(body).toContain("per_new")
    expect(logs.length).toBeGreaterThan(0)
  })
})

describe("audit summary hardening", () => {
  let directory: string

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "approval-reviewer-summary-"))
  })

  afterEach(async () => {
    await rm(directory, { recursive: true, force: true })
  })

  test("exposes truncated=false for a fully-read file and never throws on an unreadable path", async () => {
    const file = join(directory, "audit.jsonl")
    await mkdir(file, { recursive: true }) // a directory: exists but unreadable as a file
    const summary = readAuditSummary(file)
    expect(summary.exists).toBe(false)
    expect(summary.truncated).toBe(false)
    expect(summary.validRecords).toBe(0)
  })

  test("a symlinked audit file reads as missing instead of following the link", async () => {
    const target = join(directory, "target.jsonl")
    writeFileSync(target, `${JSON.stringify(record({ requestID: "per_link" }))}\n`)
    await symlink(target, join(directory, "audit.jsonl"))
    const summary = readAuditSummary(join(directory, "audit.jsonl"))
    expect(summary.exists).toBe(false)
    expect(summary.validRecords).toBe(0)
  })

  test("coerces a non-string actor name instead of throwing in the sort", () => {
    const file = join(directory, "audit.jsonl")
    const token = ["ghp_", "synthetic0123456789abcdefghijklmnopqrstuvwxyz"].join("")
    const lines = [
      JSON.stringify({
        timestamp: "2026-01-01T00:00:00.000Z",
        requestID: "r1",
        sessionID: "s1",
        permission: "bash",
        outcome: "allow",
        reason: "ok",
        actor: { name: 42, profile: "unknown" },
      }),
      JSON.stringify({
        timestamp: "2026-01-01T00:01:00.000Z",
        requestID: "r2",
        sessionID: "s2",
        permission: "bash",
        outcome: "deny",
        reason: `credential ${token}`,
        actor: { name: 42, profile: "unknown" },
      }),
    ]
    writeFileSync(file, lines.join("\n") + "\n")
    const summary = readAuditSummary(file)
    expect(summary.validRecords).toBe(2)
    expect(summary.unknownActorNames[0]!.name).toBe("42")
    expect(summary.unknownActorNames[0]!.count).toBe(2)
  })

  test("summarizes only the bounded tail when the file exceeds the read cap", async () => {
    // Mirrors AUDIT_READ_CAP_BYTES in src/audit.ts. The file is built
    // sparsely: one header line at offset 0, a hole of unwritten zeros,
    // and the tail block at a far offset, so no 64 MiB buffer is allocated
    // by the test itself. A leading newline isolates the zero hole from
    // the first tail line, so the partial-line strip only eats garbage.
    const CAP = 64 * 1024 * 1024
    const file = join(directory, "audit.jsonl")
    const headLine = `${JSON.stringify(
      record({
        requestID: "per_head",
        outcome: "allow",
        permission: "bash",
        timestamp: "2020-01-01T00:00:00.000Z",
      }),
    )}\n`
    const tailLines = [1, 2, 3].map(
      (i) =>
        `${JSON.stringify(
          record({
            requestID: `per_tail_${i}`,
            outcome: "deny",
            permission: "read",
            timestamp: `2026-05-0${i}T00:00:00.000Z`,
          }),
        )}\n`,
    )
    const tailStart = CAP + 1024
    const tailBlock = `\n${tailLines.join("")}`
    const fd = openSync(file, "w")
    try {
      writeAt(fd, headLine, 0)
      writeAt(fd, tailBlock, tailStart)
    } finally {
      closeSync(fd)
    }
    const summary = readAuditSummary(file)
    expect(summary.exists).toBe(true)
    expect(summary.truncated).toBe(true)
    expect(summary.validRecords).toBe(3)
    expect(summary.totalLines).toBe(3)
    expect(summary.invalidLines).toBe(0)
    // The header line is outside the window: no trace of it remains.
    expect(summary.byOutcome).toEqual({ deny: 3 })
    expect(summary.byPermission).toEqual({ read: 3 })
    expect(summary.firstTimestamp).toBe("2026-05-01T00:00:00.000Z")
    expect(summary.lastTimestamp).toBe("2026-05-03T00:00:00.000Z")
  }, 30_000)

  test("keeps a complete first line when the tail window starts at a line boundary", async () => {
    // Same sparse layout, but the window is aligned so its first byte is
    // the start of a whole line: a newline is planted at offset - 1 and a
    // complete boundary record at offset. The reader must keep it instead
    // of stripping it as a partial line.
    const CAP = 64 * 1024 * 1024
    const file = join(directory, "audit.jsonl")
    const headLine = `${JSON.stringify(
      record({
        requestID: "per_head",
        outcome: "allow",
        permission: "bash",
        timestamp: "2020-01-01T00:00:00.000Z",
      }),
    )}\n`
    const boundaryLine = `${JSON.stringify(
      record({
        requestID: "per_boundary",
        outcome: "allow",
        permission: "write",
        timestamp: "2026-06-01T00:00:00.000Z",
      }),
    )}\n`
    const tailLines = [1, 2].map(
      (i) =>
        `${JSON.stringify(
          record({
            requestID: `per_tail_${i}`,
            outcome: "deny",
            permission: "read",
            timestamp: `2026-06-0${i + 1}T00:00:00.000Z`,
          }),
        )}\n`,
    )
    const tailStart = CAP + 4096
    const tailBlock = `\n${tailLines.join("")}`
    const size = tailStart + Buffer.byteLength(tailBlock, "utf8")
    const offset = size - CAP
    const fd = openSync(file, "w")
    try {
      writeAt(fd, headLine, 0)
      writeAt(fd, tailBlock, tailStart)
      writeAt(fd, "\n", offset - 1)
      writeAt(fd, boundaryLine, offset)
    } finally {
      closeSync(fd)
    }
    const summary = readAuditSummary(file)
    expect(summary.exists).toBe(true)
    expect(summary.truncated).toBe(true)
    // Boundary record plus the two tail records; the zero hole between
    // them counts as a single invalid line.
    expect(summary.validRecords).toBe(3)
    expect(summary.totalLines).toBe(4)
    expect(summary.invalidLines).toBe(1)
    expect(summary.byPermission).toEqual({ read: 2, write: 1 })
    expect(summary.byOutcome).toEqual({ allow: 1, deny: 2 })
    expect(summary.firstTimestamp).toBe("2026-06-01T00:00:00.000Z")
    expect(summary.lastTimestamp).toBe("2026-06-03T00:00:00.000Z")
  }, 30_000)
})

describe("audit writer nested redaction", () => {
  let directory: string

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "approval-reviewer-nested-"))
  })

  afterEach(async () => {
    await rm(directory, { recursive: true, force: true })
  })

  test("policyTrace rule reasons and ask decisions are redacted, structure preserved", async () => {
    const file = join(directory, "audit.jsonl")
    const writer = createAuditWriter({ ...DEFAULT_CONFIG, auditPath: file })!
    const token = ["ghp_", "synthetic0123456789abcdefghijklmnopqrstuvwxyz"].join("")
    await writer(
      record({
        policyTrace: {
          effectivePolicyHash: "abcd",
          matchedRules: [{ id: "r1", source: "global", effect: "deny", reason: `token ${token}` }],
          finalRoute: "deny",
          mode: "enforce",
        },
        askDecisions: [{ at: 1, question: `use ${token}?`, answer: "yes" }],
      }),
    )
    const written = readFileSync(file, "utf8")
    expect(written).not.toContain(token)
    expect(written).toContain("[REDACTED")
    expect(written).toContain('"effectivePolicyHash":"abcd"')
    expect(written).toContain('"id":"r1"')
    expect(written).toContain('"answer":"yes"')
    expect(written).toContain('"sessionID":"ses_main"')
  })
})
