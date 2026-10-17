import { afterEach, describe, expect, test } from "bun:test"
import { execFile } from "node:child_process"
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { delimiter, join } from "node:path"
import { promisify } from "node:util"
import { enrichGitEvidence } from "../src/git-evidence.ts"
import { request } from "./helpers.ts"

const execFileAsync = promisify(execFile)
const temporaryDirectories: string[] = []

async function git(directory: string, args: string[]): Promise<void> {
  await execFileAsync("git", args, { cwd: directory })
}

async function repositoryAt(directory: string): Promise<string> {
  temporaryDirectories.push(directory)
  await mkdir(directory, { recursive: true })
  await git(directory, ["init", "-b", "staging"])
  await git(directory, ["config", "user.email", "reviewer@example.invalid"])
  await git(directory, ["config", "user.name", "Reviewer Test"])
  await writeFile(join(directory, "target.py"), "before = 1\n")
  await writeFile(join(directory, "unrelated.py"), "before = 1\n")
  await git(directory, ["add", "target.py", "unrelated.py"])
  await git(directory, ["commit", "-m", "fixture"])
  return directory
}

async function repository(): Promise<string> {
  return repositoryAt(await mkdtemp(join(tmpdir(), "approval-reviewer-git-")))
}

/** git rev-parse --show-toplevel prints forward slashes on Windows. */
function gitRepositoryPath(directory: string): string {
  return process.platform === "win32" ? directory.replaceAll("\\", "/") : directory
}

function repositoryRootOf(text: string): string | undefined {
  return (JSON.parse(text.replace(/^GIT_STATE_ANALYSIS\n/, "")) as { repositoryRoot?: string })
    .repositoryRoot
}

afterEach(async () => {
  // Sequential and force: nested fixtures push overlapping paths, so parallel
  // removals race and an already-deleted child would fail the suite.
  for (const directory of temporaryDirectories.splice(0)) {
    await rm(directory, { recursive: true, force: true })
  }
})

describe("Git state evidence enrichment", () => {
  test("remote Git commands and command mentions never resolve against the local repository", async () => {
    const directory = await repository()
    await git(directory, ["remote", "add", "origin", "https://local.example.invalid/project.git"])
    for (const command of [
      "printf git push origin",
      "ssh fixture.invalid git push origin",
      "sudo ssh fixture.invalid git push origin",
      "chroot ./root git push origin",
      "env -C other git push origin",
    ]) {
      const result = await enrichGitEvidence(
        request({ metadata: { command }, patterns: [command] }),
        directory,
        8000,
      )
      expect(result.text).toBe("")
    }
    for (const command of [
      "env -u git git push origin",
      "sudo -u fixture git push origin",
      "git >output.log push origin",
    ]) {
      const result = await enrichGitEvidence(
        request({ metadata: { command }, patterns: [command] }),
        directory,
        8000,
      )
      expect(result.text).toContain("https://local.example.invalid/project.git")
    }
  })

  test("quoted operator characters remain part of a literal remote operand", async () => {
    const directory = await repository()
    const url = "https://literal.example.invalid/a>b.git"
    const command = `git push '${url}' main`
    const result = await enrichGitEvidence(
      request({ metadata: { command }, patterns: [command] }),
      directory,
      8000,
    )
    expect(result.text).toContain(url)
  })

  test("withholds successful but incomplete Git status output", async () => {
    const directory = await mkdtemp(join(tmpdir(), "reviewer-git-output-"))
    temporaryDirectories.push(directory)
    const bin = join(directory, "bin")
    await mkdir(bin)
    const fakeGitSource = [
      "const index = process.argv.findIndex((value) => /(^|[\\\\/])git(\\\\.exe)?$/i.test(value))",
      "const args = process.argv.slice(index >= 0 ? index + 1 : 2)",
      'if (args.includes("--get-regexp")) process.exit(1)',
      'if (args.includes("--show-toplevel")) { console.log(process.cwd()); process.exit(0) }',
      'if (args.includes("status")) { process.stdout.write(process.env.REVIEWER_SYNTHETIC_GIT_STATUS ?? ""); process.exit(0) }',
      "process.exit(1)",
    ].join("\n")
    if (process.platform === "win32") {
      const script = join(bin, "fake-git.js")
      await writeFile(script, fakeGitSource)
      await execFileAsync(process.execPath, [
        "build",
        script,
        "--compile",
        "--outfile",
        join(bin, "git.exe"),
      ])
    } else {
      const executable = join(bin, "git")
      await writeFile(executable, "#!/usr/bin/env bun\n" + fakeGitSource)
      await chmod(executable, 0o755)
    }
    const entry = new URL("../src/git-evidence.ts", import.meta.url).href
    const command = "git checkout HEAD -- target.txt"
    const input = request({ patterns: [command], metadata: { command } })
    for (const stdout of ["", " M target.txt\n"]) {
      // Isolate the fake executable's PATH to this child so concurrent
      // evidence reads elsewhere keep using the real Git binary.
      const child = Bun.spawn({
        cmd: [
          process.execPath,
          "-e",
          `import { enrichGitEvidence } from ${JSON.stringify(entry)};
console.log((await enrichGitEvidence(${JSON.stringify(input)}, process.cwd(), 8000)).text)`,
        ],
        cwd: directory,
        env: {
          ...process.env,
          PATH: `${bin}${delimiter}${process.env.PATH ?? ""}`,
          REVIEWER_SYNTHETIC_GIT_STATUS: stdout,
        },
        stdout: "pipe",
        stderr: "pipe",
      })
      const [exitCode, text] = await Promise.all([child.exited, new Response(child.stdout).text()])
      expect(exitCode).toBe(0)
      const record = JSON.parse(text.replace(/^GIT_STATE_ANALYSIS\n/, ""))
      expect(record.status).toBe("unavailable")
      expect(record.reason).toContain("missing branch header")
      expect(record.planned.discardTargets).toEqual(["target.txt"])
      expect(record.branch).toBeUndefined()
    }
  }, 30_000)

  test("separates preexisting staging from files a compound command plans to add", async () => {
    const directory = await repository()
    await writeFile(join(directory, "unrelated.py"), "before = 2\n")
    await git(directory, ["add", "unrelated.py"])
    await writeFile(join(directory, "target.py"), "before = 3\n")
    const command = 'git add target.py && git commit -m "bounded change"'
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      24_000,
    )
    expect(result.text).toContain("GIT_STATE_ANALYSIS")
    expect(result.text).toContain('"branch": "staging"')
    expect(result.text).toContain('"commitRequested": true')
    expect(result.text).toContain('"plannedAdd"')
    expect(result.text).toContain("target.py")
    expect(result.text).toContain('"preexistingStaged"')
    expect(result.text).toContain("unrelated.py")
  })

  test("shows the bounded diff that checkout would discard", async () => {
    const directory = await repository()
    await writeFile(join(directory, "target.py"), "before = 99\n")
    const command = "git checkout HEAD -- target.py"
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      24_000,
    )
    expect(result.text).toContain('"discardTargets"')
    expect(result.text).toContain("target.py")
    expect(result.text).toContain('"affectedTargetNumstat": "1\\t1\\ttarget.py')
  })

  test("uses the repository selected by cd or git -C inside the approved roots", async () => {
    const outer = await mkdtemp(join(tmpdir(), "approval-reviewer-git-outer-"))
    temporaryDirectories.push(outer)
    const directory = await repositoryAt(join(outer, "workspace", "repo"))
    await writeFile(join(directory, "target.py"), "selected = true\n")

    for (const command of [
      `cd ${directory} && git checkout HEAD -- target.py`,
      `git -C ${directory} checkout HEAD -- target.py`,
    ]) {
      const result = await enrichGitEvidence(
        request({ patterns: [command], metadata: { command } }),
        outer,
        24_000,
      )
      expect(repositoryRootOf(result.text)).toBe(gitRepositoryPath(directory))
      expect(result.text).toContain('"branch": "staging"')
      expect(result.text).toContain('"affectedTargetNumstat": "1\\t1\\ttarget.py')
    }
  })

  test("blocks git inspection of a repository outside the approved roots", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "approval-reviewer-git-ws-"))
    temporaryDirectories.push(workspace)
    const elsewhere = await repository()
    await writeFile(join(elsewhere, "target.py"), "escape = true\n")

    for (const command of [
      `cd ${elsewhere} && git checkout HEAD -- target.py`,
      `git -C ${elsewhere} checkout HEAD -- target.py`,
    ]) {
      const result = await enrichGitEvidence(
        request({ patterns: [command], metadata: { command } }),
        workspace,
        8_000,
      )
      expect(result.text).toContain('"status": "unavailable"')
      expect(result.text).toContain("planned Git directory is outside approved enrichment roots")
      expect(repositoryRootOf(result.text)).not.toBe(gitRepositoryPath(elsewhere))
      expect(result.text).not.toContain('"branch": "staging"')
    }
  })

  test("blocks a symlinked planned Git directory that resolves outside the roots", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "approval-reviewer-git-link-"))
    temporaryDirectories.push(workspace)
    const elsewhere = await repository()
    const link = join(workspace, "linked-repo")
    await symlink(elsewhere, link)

    const command = "git -C linked-repo checkout HEAD -- target.py"
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      workspace,
      8_000,
    )
    expect(result.text).toContain('"status": "unavailable"')
    expect(result.text).toContain("planned Git directory is outside approved enrichment roots")
  })

  test("blocks a session directory inside a repository whose root is outside the roots", async () => {
    const outer = await repositoryAt(await mkdtemp(join(tmpdir(), "approval-reviewer-git-anc-")))
    const sessionDirectory = join(outer, "workspace")
    await mkdir(sessionDirectory)
    await writeFile(join(outer, "target.py"), "ancestor = true\n")

    const command = "git checkout HEAD -- target.py"
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      sessionDirectory,
      8_000,
    )
    expect(result.text).toContain('"status": "unavailable"')
    expect(result.text).toContain("repository root is outside approved enrichment roots")
    expect(result.text).not.toContain('"branch": "staging"')
  })

  test("allows the repository selected through a parent worktree", async () => {
    const outer = await repositoryAt(await mkdtemp(join(tmpdir(), "approval-reviewer-git-parent-")))
    const sessionDirectory = join(outer, "workspace")
    await mkdir(sessionDirectory)
    await writeFile(join(outer, "target.py"), "parent = true\n")

    const command = "git -C .. checkout HEAD -- target.py"
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      sessionDirectory,
      24_000,
      outer,
    )
    expect(repositoryRootOf(result.text)).toBe(gitRepositoryPath(outer))
    expect(result.text).toContain('"branch": "staging"')
  })

  test("marks shell-expanded planned paths as unresolved", async () => {
    const directory = await repository()
    const command = 'git add "locales/$locale/messages.json" && git commit -m i18n'
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      24_000,
    )
    expect(result.text).toContain('"unresolvedPlannedPaths"')
    expect(result.text).toContain("$locale")
  })

  test("fails closed as unavailable outside a repository", async () => {
    const directory = await mkdtemp(join(tmpdir(), "approval-reviewer-no-git-"))
    temporaryDirectories.push(directory)
    const command = "git commit -m test"
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      8_000,
    )
    expect(result.text).toContain('"status": "unavailable"')
    expect(result.text).toContain("not a git repository")
  })

  test("resolves the remote operand of a push to its configured URLs", async () => {
    const directory = await repository()
    const upstream = "https://example.invalid/upstream.git"
    await git(directory, ["remote", "add", "origin", upstream])
    const command = "git push origin staging"
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      24_000,
    )
    expect(result.text).toContain('"input": "origin"')
    expect(result.text).toContain('"kind": "configured-remote"')
    expect(result.text).toContain('"pushUrls": [')
    expect(result.text).toContain(`"${upstream}"`)
    expect(result.text).toContain(`"fetchUrl": "${upstream}"`)
    expect(result.text).toContain('"configuredRemotes"')
  }, 30_000)

  test("reports every pushurl a push would contact", async () => {
    const directory = await repository()
    await git(directory, ["remote", "add", "origin", "https://example.invalid/one.git"])
    await git(directory, [
      "remote",
      "set-url",
      "--add",
      "--push",
      "origin",
      "https://example.invalid/two.git",
    ])
    await git(directory, [
      "remote",
      "set-url",
      "--add",
      "--push",
      "origin",
      "https://example.invalid/three.git",
    ])
    const command = "git push origin staging"
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      24_000,
    )
    expect(result.text).toContain("https://example.invalid/two.git")
    expect(result.text).toContain("https://example.invalid/three.git")
  }, 30_000)

  test("options with separate values do not mask the remote operand", async () => {
    const directory = await repository()
    const upstream = "https://example.invalid/upstream.git"
    await git(directory, ["remote", "add", "origin", upstream])
    for (const command of [
      "git fetch --depth 1 origin",
      "git push -o ci.skip origin main",
      "git pull -s recursive origin main",
      "git ls-remote --sort=committerdate origin",
    ]) {
      const result = await enrichGitEvidence(
        request({ patterns: [command], metadata: { command } }),
        directory,
        24_000,
      )
      expect(result.text).toContain('"input": "origin"')
      expect(result.text).toContain('"kind": "configured-remote"')
    }
  }, 30_000)

  test("a --repo override is the push destination, not the named remote", async () => {
    const directory = await repository()
    await git(directory, ["remote", "add", "origin", "https://example.invalid/upstream.git"])
    for (const command of [
      "git push --repo https://override.example.invalid/x.git origin main",
      "git push --repo=https://override.example.invalid/x.git main",
      "git push main --repo=https://override.example.invalid/x.git",
    ]) {
      const result = await enrichGitEvidence(
        request({ patterns: [command], metadata: { command } }),
        directory,
        24_000,
      )
      expect(result.text).toContain('"input": "https://override.example.invalid/x.git"')
      expect(result.text).toContain('"kind": "literal"')
      expect(result.text).not.toContain('"kind": "configured-remote"')
    }
  }, 30_000)

  test("redacts credential userinfo embedded in literal remote URLs", async () => {
    const directory = await repository()
    const secret = "syn" + "thetic-cred"
    const command = `git push https://user:${secret}@example.invalid/x.git main`
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      24_000,
    )
    expect(result.text).toContain('"kind": "literal"')
    expect(result.text).toContain('"url": "https://<redacted>@example.invalid/x.git"')
    expect(result.text).not.toContain(secret)
  }, 30_000)

  test("redacts long URL passwords before applying evidence bounds", async () => {
    const directory = await repository()
    const password = "synthetic-password-".repeat(40)
    const url = `https://user:${password}@example.invalid/x.git`
    await git(directory, ["remote", "add", "origin", url])
    await git(directory, ["config", "branch.staging.remote", url])
    for (const command of [`git push ${url} main`, "git push origin main", "git pull"]) {
      const result = await enrichGitEvidence(
        request({ patterns: [command], metadata: { command } }),
        directory,
        24_000,
      )
      expect(result.text).toContain("https://<redacted>@example.invalid/x.git")
      expect(result.text).not.toContain("synthetic-password-")
    }
    for (const command of [
      `cd sub; git push ${url} main`,
      `git -C missing push ${url} main`,
      `git -C /outside push ${url} main`,
    ]) {
      const result = await enrichGitEvidence(
        request({ patterns: [command], metadata: { command } }),
        directory,
        24_000,
      )
      expect(result.text).toContain('"status": "unavailable"')
      expect(result.text).toContain("https://<redacted>@example.invalid/x.git")
      expect(result.text).not.toContain("synthetic-password-")
    }
  }, 30_000)

  test("redacts a credential carried only in URL username", async () => {
    const directory = await repository()
    const credential = "synthetic-private-value-123456"
    const command = `git push https://${credential}@example.invalid/x.git main`
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      24_000,
    )
    expect(result.text).toContain("https://<redacted>@example.invalid/x.git")
    expect(result.text).not.toContain(credential)
  }, 30_000)

  test("reports an operand that matches no configured remote", async () => {
    const directory = await repository()
    const command = "git push HEAD:main"
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      24_000,
    )
    expect(result.text).toContain('"input": "HEAD:main"')
    expect(result.text).toContain('"kind": "unmatched"')
    expect(result.text).toContain("matches no configured remote")
  }, 30_000)

  test("resolves the default remote for an operand-less push", async () => {
    const directory = await repository()
    const upstream = "https://example.invalid/upstream.git"
    await git(directory, ["remote", "add", "origin", upstream])
    const plain = await enrichGitEvidence(
      request({ patterns: ["git push"], metadata: { command: "git push" } }),
      directory,
      24_000,
    )
    expect(plain.text).toContain('"source": "origin fallback"')
    expect(plain.text).toContain(`"${upstream}"`)

    const mirror = "https://mirror.example.invalid/rea.git"
    await git(directory, ["remote", "add", "mirror", mirror])
    await git(directory, ["config", "remote.pushDefault", "mirror"])
    const viaPushDefault = await enrichGitEvidence(
      request({ patterns: ["git push"], metadata: { command: "git push" } }),
      directory,
      24_000,
    )
    expect(viaPushDefault.text).toContain('"source": "remote.pushDefault"')
    expect(viaPushDefault.text).toContain(`"${mirror}"`)

    // branch.*.remote may hold a URL instead of a remote name: reported as
    // the destination itself, not resolved as a name.
    await git(directory, [
      "config",
      "branch.staging.remote",
      "https://direct.example.invalid/u.git",
    ])
    const viaBranchUrl = await enrichGitEvidence(
      request({ patterns: ["git pull"], metadata: { command: "git pull" } }),
      directory,
      24_000,
    )
    expect(viaBranchUrl.text).toContain('"source": "branch remote"')
    expect(viaBranchUrl.text).toContain("https://direct.example.invalid/u.git")
    expect(viaBranchUrl.text).toContain("configured value is not a named remote")
  }, 30_000)

  test("fetch --all, pull --all and remote update report every configured remote", async () => {
    const directory = await repository()
    await git(directory, ["remote", "add", "origin", "https://example.invalid/up.git"])
    for (const command of ["git fetch --all", "git pull --all", "git remote update"]) {
      const result = await enrichGitEvidence(
        request({ patterns: [command], metadata: { command } }),
        directory,
        24_000,
      )
      expect(result.text).toContain('"source": "all configured remotes"')
      expect(result.text).toContain("origin")
    }
  }, 30_000)

  test("operands beyond the resolution cap are counted as omitted", async () => {
    const directory = await repository()
    for (const name of ["a", "b", "c", "d", "e", "f", "g"]) {
      await git(directory, ["remote", "add", name, `https://example.invalid/${name}.git`])
    }
    // One remote operand per network command: push's extra positionals are
    // refspecs, not repositories.
    const command =
      "git fetch a && git fetch b && git fetch c && git fetch d && git fetch e && git fetch f && git fetch g"
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      24_000,
    )
    expect(result.text).toContain('"remoteTargetsOmitted": 2')
  }, 30_000)

  test("remote set-url surfaces the rewritten destination", async () => {
    const directory = await repository()
    await git(directory, ["remote", "add", "origin", "https://old.example.invalid/u.git"])
    const command = "git remote set-url origin https://new.example.invalid/u.git"
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      24_000,
    )
    expect(result.text).toContain('"input": "origin"')
    expect(result.text).toContain('"input": "https://new.example.invalid/u.git"')
    expect(result.text).toContain('"kind": "literal"')
  }, 30_000)

  test("commands without network subcommands carry no remote evidence", async () => {
    const directory = await repository()
    const command = 'git add target.py && git commit -m "local only"'
    const result = await enrichGitEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      24_000,
    )
    expect(result.text).not.toContain("remoteTargets")
    expect(result.text).not.toContain("defaultRemotes")
  }, 30_000)
})
