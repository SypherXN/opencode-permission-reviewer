import { basename } from "node:path"
import { isCommandAbsolute, resolveCommandPath } from "./shell-path.ts"
import { localExecutableCommand } from "./evidence/local-command.ts"
import type { PermissionRequest } from "./types.ts"
import { sourceCommand } from "./evidence/source-command.ts"
import {
  analyzeScriptContent,
  includeEvidenceFile,
  shellCommandSegmentsWithDirectory,
  type FileEvidence,
} from "./ssh-evidence.ts"

export interface LocalScriptEnrichmentResult {
  text: string
}

const INTERPRETERS = new Set([
  "python",
  "python3",
  "node",
  "bun",
  "deno",
  "tsx",
  "bash",
  "sh",
  "zsh",
  "ruby",
  "perl",
])

const INLINE_CODE_OPTIONS = new Set(["-c", "-e", "--eval", "-p", "--print", "-s", "--stdin"])
const OPTIONS_WITH_VALUE = new Set([
  "-W",
  "-X",
  "-r",
  "--require",
  "--loader",
  "--import",
  "-I",
  "-M",
  "-m",
])

// Bun subcommands whose operand names a package or workspace, never a local
// script file. `run` is absent: it accepts a direct file target and is handled
// by the interpreter spec below.
const BUN_SUBCOMMANDS = new Set([
  "add",
  "build",
  "create",
  "install",
  "link",
  "pm",
  "publish",
  "remove",
  "test",
  "unlink",
  "update",
  "x",
])

interface InterpreterSpec {
  // Subcommands whose first non-option operand executes a local file.
  fileTargetSubcommands?: Set<string>
  // Options that consume the next token as their value; the value is never
  // the script target.
  valueOptions?: Set<string>
  // Tokens that OPTIONS_WITH_VALUE consumes for other interpreters but this
  // runtime treats as non-consuming flags (their value syntax is `=`, or they
  // are repeated permission shorts).
  noConsumeOptions?: Set<string>
  // Options after which the executed file cannot be determined reliably;
  // gathering nothing beats attaching the wrong file.
  bailOptions?: Set<string>
  // Subcommands whose operand is never a local file.
  nonFileSubcommands?: Set<string>
  // A subcommand-less invocation still executes a file operand: require the
  // path-like shape so unrecognized subcommands gather nothing.
  directRequiresPathLike?: boolean
}

// A script operand that names a file. Bare operands may resolve to manifest
// scripts or package specifiers, so only separator- or extension-bearing
// operands are classified as files; anything else conservatively gathers no
// evidence. Scheme-bearing operands (https:, jsr:, npm:, node:, ...) are
// remote or package references, not local paths. A Windows drive or UNC path
// is a local file on that host; the scheme test would otherwise treat
// `C:\task.ts` as the `C:` scheme.
function pathLikeFileTarget(token: string): boolean {
  if (
    process.platform === "win32" &&
    (/^[A-Za-z]:[\\/]/.test(token) || token.startsWith("\\\\"))
  )
    return true
  if (/^[a-z][a-z0-9+.-]*:/i.test(token)) return false
  return (
    token.includes("/") ||
    (process.platform === "win32" && token.includes("\\")) ||
    /\.(?:[mc]?[jt]sx?)$/i.test(token)
  )
}

// Deno permission shorts and require-equals flags never consume the next
// token even though other runtimes use the same spellings with a value.
const DENO_NO_CONSUME = new Set(["-r", "-W", "-I"])

// Node flags that consume the next token when written without `=`; tsx
// forwards every flag it does not own, so tsx inherits the same table.
const NODE_VALUE_OPTIONS = new Set([
  "-C",
  "--conditions",
  "--env-file",
  "--env-file-if-exists",
  "--experimental-loader",
  "--test-reporter-destination",
  "--test-reporter",
  "--test-name-pattern",
  "--test-skip-pattern",
  "--test-concurrency",
  "--test-timeout",
  "--test-shard",
  "--input-type",
  "--inspect-port",
  "--inspect-publish-uid",
  "--diagnostic-dir",
  "--snapshot-blob",
  "--icu-data-dir",
  "--openssl-config",
  "--redirect-warnings",
  "--heapsnapshot-signal",
])

const INTERPRETER_SPECS: Record<string, InterpreterSpec> = {
  node: {
    valueOptions: NODE_VALUE_OPTIONS,
  },
  bun: {
    fileTargetSubcommands: new Set(["run"]),
    valueOptions: new Set([
      "-F",
      "--filter",
      "--elide-lines",
      "--shell",
      "--env-file",
      "--preload",
      "--tsconfig-override",
    ]),
    bailOptions: new Set(["--cwd", "--config"]),
    nonFileSubcommands: BUN_SUBCOMMANDS,
  },
  deno: {
    fileTargetSubcommands: new Set(["run", "serve", "watch"]),
    valueOptions: new Set([
      "-c",
      "--config",
      "--import-map",
      "--importmap",
      "--conditions",
      "--location",
      "--cert",
      "--ext",
      "--seed",
      "-L",
      "--log-level",
      "--preload",
      "--minimum-dependency-age",
      "--min-dep-age",
      "--inspect-publish-uid",
      "--cpu-prof-dir",
      "--cpu-prof-name",
      "--cpu-prof-interval",
      "--lock",
      "--port",
      "--host",
    ]),
    noConsumeOptions: DENO_NO_CONSUME,
    directRequiresPathLike: true,
  },
  tsx: {
    fileTargetSubcommands: new Set(["watch"]),
    valueOptions: new Set([
      "--tsconfig",
      "--include",
      "--exclude",
      "--ignore",
      "--env-file",
      "--env-file-if-exists",
      "-C",
      "--conditions",
      "--watch-path",
      "--experimental-loader",
      ...NODE_VALUE_OPTIONS,
    ]),
  },
}

function matchesOption(token: string, options: Set<string>): boolean {
  if (options.has(token)) return true
  return [...options].some((option) => token.startsWith(`${option}=`))
}

function scriptPath(
  tokens: string[],
  interpreterIndex: number,
  interpreter: string,
): string | undefined {
  const spec = INTERPRETER_SPECS[interpreter]
  let fileTargetPending = false
  let optionsEnded = false
  for (let index = interpreterIndex + 1; index < tokens.length; index += 1) {
    const token = tokens[index]!
    if (token === "--" && !optionsEnded) {
      optionsEnded = true
      continue
    }
    if (
      !optionsEnded &&
      (["--help", "--version"].includes(token) ||
        (["node", "bun", "deno", "tsx"].includes(interpreter) && token === "-v") ||
        (["python", "python3"].includes(interpreter) && token === "-V"))
    )
      return
    const inlineOption = [...INLINE_CODE_OPTIONS].find((option) =>
      option.startsWith("--")
        ? token === option || token.startsWith(`${option}=`)
        : token.startsWith(option),
    )
    // A dash spell can mean inline code for one runtime and a valued option
    // for another (deno -c is --config, node -c is --check): the interpreter
    // spec wins.
    if (
      token === "-" ||
      (!optionsEnded && inlineOption !== undefined && !spec?.valueOptions?.has(inlineOption)) ||
      (!optionsEnded && token.startsWith("-m"))
    ) {
      return
    }
    if (!optionsEnded && spec?.bailOptions !== undefined && matchesOption(token, spec.bailOptions))
      return
    if (!optionsEnded && spec?.noConsumeOptions?.has(token)) continue
    if (!optionsEnded && (OPTIONS_WITH_VALUE.has(token) || spec?.valueOptions?.has(token))) {
      index += 1
      continue
    }
    if (!optionsEnded && token.startsWith("-")) continue
    if (spec?.fileTargetSubcommands?.has(token) && !fileTargetPending) {
      fileTargetPending = true
      continue
    }
    if (/[$`*?{}<>]/.test(token)) return
    // The first non-option operand after a file-target subcommand is
    // decisive: a path-like token is the executed file, anything else is a
    // manifest script or package reference.
    if (fileTargetPending) return pathLikeFileTarget(token) ? token : undefined
    if (spec?.directRequiresPathLike && !pathLikeFileTarget(token)) return
    if (spec?.nonFileSubcommands?.has(token)) return
    return token
  }
  return
}

function recordFor(interpreter: string, path: string, file: FileEvidence): Record<string, unknown> {
  return {
    kind: "local_script",
    interpreter,
    path,
    status: file.status,
    ...(file.reason === undefined ? {} : { reason: file.reason }),
    ...(file.size === undefined ? {} : { size: file.size }),
    ...(file.includedBytes === undefined ? {} : { includedBytes: file.includedBytes }),
    ...(file.includedSha256 === undefined ? {} : { includedSha256: file.includedSha256 }),
    ...(file.content === undefined
      ? {}
      : {
          signals: analyzeScriptContent(file.content),
          content: file.content,
        }),
  }
}

export async function enrichLocalScriptEvidence(
  request: PermissionRequest,
  directory: string,
  worktree: string,
  maxChars: number,
): Promise<LocalScriptEnrichmentResult> {
  if (request.permission !== "bash") return { text: "" }
  const segments = shellCommandSegmentsWithDirectory(sourceCommand(request), directory)
  const records: Array<Record<string, unknown>> = []
  const seen = new Set<string>()

  for (const segment of segments) {
    const command = localExecutableCommand(segment.tokens)?.tokens
    if (!command || !INTERPRETERS.has(basename(command[0] ?? ""))) continue
    const interpreter = basename(command[0]!)
    const path = scriptPath(command, 0, interpreter)
    if (!path) continue
    const key = `${interpreter}\0${segment.directory === undefined && !isCommandAbsolute(path) ? `unresolved:${path}` : resolveCommandPath(segment.directory ?? directory, path)}`
    if (seen.has(key)) continue
    seen.add(key)
    const file =
      segment.directory === undefined && !isCommandAbsolute(path)
        ? {
            source: "file" as const,
            path,
            status: "unavailable" as const,
            reason: segment.directoryReason ?? "working directory is unresolved",
          }
        : await includeEvidenceFile(
            path,
            segment.directory ?? directory,
            directory,
            worktree,
            maxChars,
          )
    records.push(recordFor(interpreter, file.path, file))
  }

  if (records.length === 0) return { text: "" }
  const serialized = JSON.stringify(records, null, 2)
  const bounded =
    serialized.length <= maxChars
      ? serialized
      : `${serialized.slice(0, maxChars)}\n<local_script_enrichment_truncated characters="${serialized.length - maxChars}" />`
  return { text: `LOCAL_SCRIPT_ANALYSIS\n${bounded}` }
}
