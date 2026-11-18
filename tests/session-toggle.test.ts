import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runCli } from "../src/cli/explain.ts"
import {
  DEFAULT_SESSION_TOGGLE_PATH,
  oprDisabled,
  readSessionToggle,
  resolveSessionTogglePath,
  sessionDisabled,
  sessionToggleActive,
  setDirectoryOff,
  setDirectoryOn,
  setSessionOff,
  setSessionOn,
  SESSION_TOGGLE_PATH_ENV,
} from "../src/session-toggle.ts"

const previousSessions = process.env[SESSION_TOGGLE_PATH_ENV]
const previousIsolation = process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR

let dir: string
let path: string

function writeRaw(content: string): void {
  writeFileSync(path, content)
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "reviewer-session-toggle-"))
  path = join(dir, "sessions.json")
  process.env[SESSION_TOGGLE_PATH_ENV] = path
  // Keep the CLI away from the real isolation folder if it ever loads it.
  process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = join(dir, "isolation")
})

afterEach(() => {
  if (previousSessions === undefined) delete process.env[SESSION_TOGGLE_PATH_ENV]
  else process.env[SESSION_TOGGLE_PATH_ENV] = previousSessions
  if (previousIsolation === undefined) delete process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR
  else process.env.OPENCODE_PERMISSION_REVIEWER_ISOLATION_DIR = previousIsolation
  rmSync(dir, { recursive: true, force: true })
})

describe("session toggle reader", () => {
  test("defaults to on when the file is absent", async () => {
    expect(resolveSessionTogglePath()).toBe(path)
    expect(DEFAULT_SESSION_TOGGLE_PATH.endsWith("permission-reviewer-sessions.json")).toBe(true)
    expect(readSessionToggle(path)).toBeUndefined()
    expect(sessionDisabled("ses_a", Date.now(), path)).toEqual({ disabled: false })
  })

  test("reports a session off while its entry is present", async () => {
    writeRaw(
      JSON.stringify({ version: 1, off: { ses_a: { reason: "pairing on the debug session" } } }),
    )
    expect(sessionDisabled("ses_a", Date.now(), path)).toEqual({
      disabled: true,
      reason: "pairing on the debug session",
    })
    expect((await readSessionToggle(path))!.off.ses_a).toEqual({
      reason: "pairing on the debug session",
    })
  })

  test("an expired until is on again", async () => {
    writeRaw(
      JSON.stringify({
        version: 1,
        off: { ses_a: { until: new Date(Date.now() - 60_000).toISOString() } },
      }),
    )
    expect(sessionDisabled("ses_a", Date.now(), path)).toEqual({ disabled: false })
    expect(sessionToggleActive({}, Date.now())).toBe(true)
  })

  test("a future until is still off", async () => {
    const until = new Date(Date.now() + 60_000).toISOString()
    writeRaw(JSON.stringify({ version: 1, off: { ses_a: { until } } }))
    expect(sessionDisabled("ses_a", Date.now(), path)).toEqual({ disabled: true, until })
  })

  test("malformed or wrong-version files are on", async () => {
    for (const content of [
      "{ not json",
      "[]",
      "null",
      JSON.stringify({ version: 2, off: { ses_a: {} } }),
      JSON.stringify({ version: 1, off: [] }),
      JSON.stringify({ version: 1, off: { ses_a: { until: 42 } } }),
    ]) {
      writeRaw(content)
      expect(sessionDisabled("ses_a", Date.now(), path)).toEqual({ disabled: false })
    }
  })

  test("another session's entry does not disable this session", async () => {
    writeRaw(JSON.stringify({ version: 1, off: { ses_b: {} } }))
    expect(sessionDisabled("ses_a", Date.now(), path)).toEqual({ disabled: false })
    // Inherited object keys are not entries.
    expect(sessionDisabled("constructor", Date.now(), path)).toEqual({ disabled: false })
  })

  test("an unreadable path is on", async () => {
    // A directory at the path cannot be read as a file.
    const unreadable = join(dir, "sessions-dir")
    mkdirSync(unreadable)
    expect(sessionDisabled("ses_a", Date.now(), unreadable)).toEqual({ disabled: false })
  })
})

describe("session toggle writer and CLI", () => {
  test("off then read is off, with a bounded one-line reason", async () => {
    await setSessionOff("ses_a", { reason: "line one\nline two", minutes: 30 }, path)
    const status = sessionDisabled("ses_a", Date.now(), path)
    expect(status.disabled).toBe(true)
    expect(status.reason).toBe("line one line two")
    expect(Date.parse(status.until!)).toBeGreaterThan(Date.now())
  })

  test("on removes the entry and preserves other sessions", async () => {
    await setSessionOff("ses_a", {}, path)
    await setSessionOff("ses_b", {}, path)
    await setSessionOn("ses_a", path)
    const state = await readSessionToggle(path)
    expect(Object.hasOwn(state!.off, "ses_a")).toBe(false)
    expect(Object.hasOwn(state!.off, "ses_b")).toBe(true)
    expect(await setSessionOn("ses_a", path)).toBe(false)
  })

  test("CLI off then read is off, CLI on removes the entry", async () => {
    expect(await runCli(["opr", "off", "--session", "ses_cli", "--reason", "cli test"])).toBe(0)
    expect(sessionDisabled("ses_cli", Date.now(), path)).toEqual({
      disabled: true,
      reason: "cli test",
    })

    expect(await runCli(["opr", "status"])).toBe(0)
    expect(await runCli(["opr", "on", "--session", "ses_cli"])).toBe(0)
    expect(Object.keys((await readSessionToggle(path))!.off)).toEqual([])
    expect(sessionDisabled("ses_cli", Date.now(), path)).toEqual({ disabled: false })

    expect(await runCli(["opr", "off", "--session", "ses_cli", "--minutes", "0"])).toBe(2)
    expect(await runCli(["opr", "bogus"])).toBe(2)
  })

  test("a directory entry covers every session in it and not another folder", async () => {
    const folder = join(dir, "project")
    await setDirectoryOff(folder, { reason: "pairing" }, path)
    expect(oprDisabled("ses_any", folder, Date.now(), path)).toEqual({
      disabled: true,
      reason: "pairing",
    })
    // Another folder stays on.
    expect(oprDisabled("ses_any", join(dir, "other"), Date.now(), path)).toEqual({
      disabled: false,
    })
    expect(oprDisabled("ses_any", undefined, Date.now(), path)).toEqual({ disabled: false })
    // A lapsed directory entry is on again.
    await setDirectoryOff(folder, { minutes: 5, now: Date.now() - 10 * 60_000 }, path)
    expect(oprDisabled("ses_any", folder, Date.now(), path)).toEqual({ disabled: false })

    await setDirectoryOff(folder, {}, path)
    expect(await setDirectoryOn(folder, path)).toBe(true)
    expect(await setDirectoryOn(folder, path)).toBe(false)
    expect(oprDisabled("ses_any", folder, Date.now(), path)).toEqual({ disabled: false })
  })

  test("a session entry and a directory entry both apply", async () => {
    const folder = join(dir, "project")
    await setSessionOff("ses_own", { reason: "one chat" }, path)
    await setDirectoryOff(folder, { reason: "the folder" }, path)
    expect(oprDisabled("ses_own", folder, Date.now(), path)).toEqual({
      disabled: true,
      reason: "one chat",
    })
    expect(oprDisabled("ses_other", folder, Date.now(), path)).toEqual({
      disabled: true,
      reason: "the folder",
    })
  })

  test("CLI without --session switches the current directory", async () => {
    expect(await runCli(["opr", "off", "--reason", "folder test"])).toBe(0)
    expect(oprDisabled("ses_folder", process.cwd(), Date.now(), path)).toEqual({
      disabled: true,
      reason: "folder test",
    })
    expect(await runCli(["opr", "status"])).toBe(0)
    expect(await runCli(["opr", "on"])).toBe(0)
    expect(oprDisabled("ses_folder", process.cwd(), Date.now(), path)).toEqual({
      disabled: false,
    })
  })

  test("atomic write leaves one valid file behind and no temp files", async () => {
    expect(await runCli(["opr", "off", "--session", "ses_a"])).toBe(0)
    expect(await runCli(["opr", "off", "--session", "ses_b", "--minutes", "5"])).toBe(0)
    const raw = readFileSync(path, "utf8")
    const parsed = JSON.parse(raw) as { version: number; off: Record<string, unknown> }
    expect(parsed.version).toBe(1)
    expect(Object.keys(parsed.off).sort()).toEqual(["ses_a", "ses_b"])
    expect(readdirSync(dir).filter((name) => name.includes(".tmp"))).toEqual([])
  })
})
