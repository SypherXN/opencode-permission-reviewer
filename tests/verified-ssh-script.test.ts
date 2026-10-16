import { afterEach, describe, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { execFile } from "node:child_process"
import { promisify } from "node:util"
import { existsSync } from "node:fs"
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { delimiter, join } from "node:path"
import { MockClient, request } from "./helpers.ts"
import { assembleEvidence, defaultEvidenceProviders } from "../src/context/evidence-assembler.ts"
import { buildEvidenceResult } from "../src/context.ts"
import { DEFAULT_CONFIG } from "../src/config.ts"
import { evaluateReview } from "../src/core/review-engine.ts"
import type { ReviewEnvelope } from "../src/types.ts"
import {
  collectVerifiedSshScript,
  parseVerifiedSshScriptCommand,
  renderVerifiedSshScriptCommand,
  ScriptAnalysisRegistry,
  VERIFIED_SCRIPT_LIMIT,
} from "../src/verified-ssh-script.ts"

const execFileAsync = promisify(execFile)
const directories: string[] = []

async function fixture(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "approval-reviewer-verified-"))
  directories.push(directory)
  return directory
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true })))
})

function digest(content: string): string {
  return createHash("sha256").update(content).digest("hex")
}

describe("verified SSH script protocol", () => {
  test("recognizes only the canonical hash-checked command", () => {
    const command = renderVerifiedSshScriptCommand({
      path: "/tmp/opencode/deploy.sh",
      destination: "deploy@example.invalid",
      port: 2222,
      sha256: digest("echo safe\n"),
      shell: "bash",
    })
    expect(parseVerifiedSshScriptCommand(request({ metadata: { command } }))).toMatchObject({
      path: "/tmp/opencode/deploy.sh",
      destination: "deploy@example.invalid",
      port: 2222,
    })
    for (const altered of [
      `${command}; echo extra`,
      command.replace("sha256sum $f", "cat $f"),
      command.replace("cat -- ", "sed -n '1,9p' "),
      command.replace("bash $f", "bash $f; echo extra"),
    ])
      expect(
        parseVerifiedSshScriptCommand(request({ metadata: { command: altered } })),
      ).toBeUndefined()
  })

  test("reads a 28 KiB script once and reuses only its analysis for the same scope", async () => {
    const directory = await fixture()
    const path = join(directory, "deploy.sh")
    const content = "# deployment script\n" + "echo safe\n".repeat(2800)
    await writeFile(path, content)
    const command = {
      path,
      destination: "deploy@example.invalid",
      sha256: digest(content),
      shell: "bash" as const,
    }
    const registry = new ScriptAnalysisRegistry()
    const first = await collectVerifiedSshScript(
      command,
      directory,
      directory,
      "session-a",
      "config-a",
      registry,
    )
    expect(first.status).toBe("full")
    expect(first.text).toContain(content)
    registry.rememberApproved(first, {
      version: 2,
      outcome: "allow",
      risk_level: "high",
      user_authorization: "high",
      scope_alignment: "aligned",
      evidence_completeness: "sufficient",
      rationale: "Authorized bounded deployment.",
      confidence: 0.9,
      script_analysis:
        "Starts the deployment services and checks their health without deleting data.",
    })
    const second = await collectVerifiedSshScript(
      command,
      directory,
      directory,
      "session-a",
      "config-a",
      registry,
    )
    expect(second.status).toBe("reused")
    expect(second.text).not.toContain(content)
    expect(second.text).toContain("not authorization")
    expect(
      (
        await collectVerifiedSshScript(
          command,
          directory,
          directory,
          "session-b",
          "config-a",
          registry,
        )
      ).status,
    ).toBe("full")
    expect(
      (
        await collectVerifiedSshScript(
          command,
          directory,
          directory,
          "session-a",
          "config-b",
          registry,
        )
      ).status,
    ).toBe("full")
    expect(
      (
        await collectVerifiedSshScript(
          { ...command, destination: "other.invalid" },
          directory,
          directory,
          "session-a",
          "config-a",
          registry,
        )
      ).status,
    ).toBe("full")
    await writeFile(path, `${content}echo changed\n`)
    expect(
      (
        await collectVerifiedSshScript(
          command,
          directory,
          directory,
          "session-a",
          "config-a",
          registry,
        )
      ).status,
    ).toBe("unavailable")
  })

  test("fails closed on oversized, missing, or credential-bearing files", async () => {
    const directory = await fixture()
    const path = join(directory, "deploy.sh")
    const registry = new ScriptAnalysisRegistry()
    const command = { path, destination: "host.invalid", sha256: digest("x"), shell: "sh" as const }
    expect(
      (await collectVerifiedSshScript(command, directory, directory, "s", "c", registry)).status,
    ).toBe("unavailable")
    const large = "x".repeat(VERIFIED_SCRIPT_LIMIT + 1)
    await writeFile(path, large)
    expect(
      (
        await collectVerifiedSshScript(
          { ...command, sha256: digest(large) },
          directory,
          directory,
          "s",
          "c",
          registry,
        )
      ).status,
    ).toBe("unavailable")
    const secret = `api_key = "${"sk-" + "syntheticcredential123456789"}"\n`
    await writeFile(path, secret)
    expect(
      (
        await collectVerifiedSshScript(
          { ...command, sha256: digest(secret) },
          directory,
          directory,
          "s",
          "c",
          registry,
        )
      ).status,
    ).toBe("unavailable")
  })

  test("remote hash guard stops changed bytes before invoking the script", async () => {
    const directory = await fixture()
    const path = join(directory, "deploy.sh")
    const blockedMarker = join(directory, "blocked")
    const approvedMarker = join(directory, "executed")
    const original = "printf done > executed\n"
    await writeFile(path, original)
    if (process.platform === "win32") {
      const realSh = (process.env.PATH ?? "")
        .split(delimiter)
        .map((entry) => join(entry, "sh.exe"))
        .find((candidate) => existsSync(candidate))
      if (realSh === undefined) throw new Error("Git sh.exe is not on PATH")
      const fakeSsh = join(directory, "ssh.exe")
      const fakeShell = join(directory, "sh.exe")
      const sshScript = join(directory, "fake-ssh.js")
      const shellScript = join(directory, "fake-sh.js")
      await writeFile(
        sshScript,
        [
          'import { spawn } from "node:child_process"',
          'let index = -1; const slash = String.fromCharCode(92); process.argv.forEach((value, i) => { const name = value.toLowerCase().split(slash).pop().split("/").pop(); if (name === "ssh.exe" || name === "ssh") index = i })',
          "const args = process.argv.slice(index >= 0 ? index + 1 : 1)",
          'const remote = args.at(-1) ?? ""',
          `const realSh = ${JSON.stringify(realSh)}`,
          'const child = spawn(realSh, ["-c", remote], { stdio: "inherit" })',
          'child.on("exit", (code) => process.exit(code ?? 1))',
          'child.on("error", () => process.exit(1))',
          "",
        ].join("\n"),
      )
      await writeFile(
        shellScript,
        [
          'import { spawn } from "node:child_process"',
          `const realSh = ${JSON.stringify(realSh)}`,
          'let index = -1; const slash = String.fromCharCode(92); process.argv.forEach((value, i) => { const name = value.toLowerCase().split(slash).pop().split("/").pop(); if (name === "sh.exe" || name === "sh") index = i })',
          "const args = process.argv.slice(index >= 0 ? index + 1 : 1)",
          'const flag = args.indexOf("-c")',
          'if (flag >= 0 && typeof args[flag + 1] === "string")',
          '  args[flag + 1] = args[flag + 1].replace(/\\bssh\\b/g, "./ssh.exe")',
          'const child = spawn(realSh, args, { stdio: "inherit" })',
          'child.on("exit", (code) => process.exit(code ?? 1))',
          'child.on("error", () => process.exit(1))',
          "",
        ].join("\n"),
      )
      await execFileAsync(process.execPath, ["build", sshScript, "--compile", "--outfile", fakeSsh])
      await execFileAsync(process.execPath, ["build", shellScript, "--compile", "--outfile", fakeShell])
    } else {
      const fakeSsh = join(directory, "ssh")
      await writeFile(fakeSsh, '#!/bin/sh\nfor arg do remote=$arg; done\nexec sh -c "$remote"\n', {
        mode: 0o700,
      })
    }
    const command = renderVerifiedSshScriptCommand({
      path: "deploy.sh",
      destination: "host.invalid",
      sha256: digest(original),
      shell: "bash",
    })
    const env = { ...process.env, PATH: `${directory}${delimiter}${process.env.PATH ?? ""}` }
    await writeFile(path, "printf changed > blocked\n")
    await expect(execFileAsync("sh", ["-c", command], { env, cwd: directory })).rejects.toThrow()
    await expect(stat(blockedMarker)).rejects.toThrow()
    await writeFile(path, original)
    await execFileAsync("sh", ["-c", command], { env, cwd: directory })
    expect(await readFile(approvedMarker, "utf8")).toBe("done")
  })

  test("assembles complete first evidence and a compact follow-up for both hosts", async () => {
    const directory = await fixture()
    const path = join(directory, "deploy.sh")
    const content = "echo inspected\n".repeat(1900)
    await writeFile(path, content)
    const command = renderVerifiedSshScriptCommand({
      path: "deploy.sh",
      destination: "host.invalid",
      sha256: digest(content),
      shell: "bash",
    })
    const registry = new ScriptAnalysisRegistry()
    const client = new MockClient()
    const pending = request({ metadata: { command }, patterns: [command] })
    const ctx = {
      client,
      directory,
      worktree: directory,
      config: DEFAULT_CONFIG,
      scriptRegistry: registry,
    }
    const first = await assembleEvidence(pending, defaultEvidenceProviders(), ctx)
    expect(first.verifiedScript?.status).toBe("full")
    const firstPrompt = buildEvidenceResult(first, DEFAULT_CONFIG)
    expect(firstPrompt.actionEvidenceComplete).toBe(true)
    expect(firstPrompt.text).toContain(content)
    expect(firstPrompt.text.match(/echo inspected/g)?.length).toBe(1900)
    registry.rememberApproved(first.verifiedScript, {
      version: 2,
      outcome: "allow",
      risk_level: "medium",
      user_authorization: "high",
      scope_alignment: "aligned",
      evidence_completeness: "sufficient",
      rationale: "Bounded authorized deployment.",
      confidence: 0.9,
      script_analysis:
        "Runs a fixed diagnostic command without deleting files or accessing credentials.",
    })
    const next = await assembleEvidence(pending, defaultEvidenceProviders(), ctx)
    expect(next.verifiedScript?.status).toBe("reused")
    const nextPrompt = buildEvidenceResult(next, DEFAULT_CONFIG)
    expect(nextPrompt.actionEvidenceComplete).toBe(true)
    expect(nextPrompt.text).not.toContain(content)
    expect(nextPrompt.text).toContain("Prior model-generated script analysis")
  })

  test("CLI generates the accepted command without printing script content", async () => {
    const directory = await fixture()
    const path = join(directory, "deploy.sh")
    await writeFile(path, "echo private workflow details\n")
    const { stdout } = await execFileAsync(
      "bun",
      [
        join(import.meta.dir, "../src/cli/explain.ts"),
        "script",
        "command",
        "--file",
        "deploy.sh",
        "--host",
        "host.invalid",
      ],
      { cwd: directory },
    )
    expect(stdout).not.toContain("private workflow details")
    expect(
      parseVerifiedSshScriptCommand(request({ metadata: { command: stdout.trim() } })),
    ).toBeDefined()
  })

  test("an opaque remote script denial gives the agent a concrete recovery path", async () => {
    const pending = request({
      metadata: { command: "ssh host.invalid 'bash /tmp/deploy.sh'" },
      patterns: ["ssh host.invalid 'bash /tmp/deploy.sh'"],
    })
    const envelope: ReviewEnvelope = {
      request: pending,
      directory: "/project",
      worktree: "/project",
      transcript: "",
      intentHistory: "",
      enrichment: "",
      sshAudit: [],
    }
    for (const reason of ["Remote script content is incomplete.", "El script aparece truncado."]) {
      const result = await evaluateReview(
        pending,
        { ...DEFAULT_CONFIG, escalationMode: "deny" },
        {
          collect: async () => envelope,
          review: async () => ({ kind: "escalate", reason }),
          active: () => true,
          auxiliarySession: () => false,
          observe: () => {},
        },
      )
      expect(result.kind).toBe("deny")
      expect(result.reason).toContain("opencode-permission-reviewer script command")
    }
  })
})
