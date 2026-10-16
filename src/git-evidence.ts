import { execFile } from "node:child_process"
import { realpath } from "node:fs/promises"
import { promisify } from "node:util"
import { basename } from "node:path"
import { resolveCommandPath } from "./shell-path.ts"
import type { PermissionRequest } from "./types.ts"
import { sourceCommand } from "./evidence/source-command.ts"
import { localExecutableCommand } from "./evidence/local-command.ts"
import {
  approvedEvidenceRoots,
  isWithinRoot,
  shellCommandSegmentsWithDirectory,
} from "./ssh-evidence.ts"

const execFileAsync = promisify(execFile)

export interface GitEnrichmentResult {
  text: string
}

interface PlannedGitActions {
  relevant: boolean
  commit: boolean
  plannedAdd: string[]
  discardTargets: string[]
  removeTargets: string[]
  commands: string[]
  rewriteBases: string[]
  /** Remote operands as written (configured names, literal URLs) collected
   *  from network subcommands. Resolution to URLs happens later, inside the
   *  containment envelope. */
  remoteCandidates: string[]
  /** Network subcommands whose operand list had no explicit remote, so git
   *  will contact the branch/default-configured remote instead. */
  needsDefaultRemote: string[]
  executionDirectory?: string
  directoryReason?: string
}

/** Subcommands whose first positional names (or implies) a remote. */
const GIT_REMOTE_COMMANDS = new Set(["push", "fetch", "pull", "ls-remote", "remote"])

/** Verbs of `git remote` that operate on a named remote as their next
 *  positional. `update` takes an optional group, not a remote name. */
const REMOTE_VERBS_WITH_NAME = new Set([
  "prune",
  "show",
  "get-url",
  "set-url",
  "set-head",
  "rename",
  "remove",
  "rm",
])

/** Options of the network subcommands that consume a separate value token.
 *  Without skipping the value, `git fetch --depth 1 origin` would report "1"
 *  as the remote operand and hide the real destination. Options with an
 *  OPTIONAL value (`--force-with-lease`, `--rebase`, `--signed`, …) are
 *  deliberately absent: git requires `=` for those, and skipping the next
 *  token would swallow the remote instead. */
const NETWORK_VALUE_OPTIONS: Record<string, Set<string>> = {
  push: new Set(["-o", "--push-option", "--receive-pack", "--exec", "--repo"]),
  fetch: new Set([
    "--depth",
    "--deepen",
    "--shallow-since",
    "--shallow-exclude",
    "-j",
    "--jobs",
    "--refmap",
    "--upload-pack",
    "-o",
    "--server-option",
    "--negotiation-tip",
    "--filter",
  ]),
  pull: new Set([
    "--depth",
    "--deepen",
    "--shallow-since",
    "--shallow-exclude",
    "-j",
    "--jobs",
    "--refmap",
    "--upload-pack",
    "-o",
    "--server-option",
    "--negotiation-tip",
    "--filter",
    "-s",
    "--strategy",
    "-X",
    "--strategy-option",
  ]),
  "ls-remote": new Set(["--sort", "--upload-pack", "-o", "--server-option"]),
  remote: new Set(),
}

/** First positional operand of a network subcommand, skipping options and
 *  their separate values. Returns the operand plus any `--repo`-style
 *  override value, which is itself a push destination. */
function networkOperand(
  tokens: string[],
  index: number,
  subcommand: string,
): { operand?: string | undefined; repoOverride?: string | undefined } {
  const valueOpts = NETWORK_VALUE_OPTIONS[subcommand] ?? new Set<string>()
  let afterSeparator = false
  let operand: string | undefined
  let repoOverride: string | undefined
  for (let cursor = index + 1; cursor < tokens.length; cursor += 1) {
    const token = tokens[cursor]!
    if (token === "--") {
      afterSeparator = true
      continue
    }
    if (!afterSeparator && token.startsWith("-") && token.length > 1) {
      if (token === "--repo" && cursor + 1 < tokens.length) {
        repoOverride = tokens[++cursor]
        continue
      }
      if (subcommand === "push" && token.startsWith("--repo=")) {
        repoOverride = token.slice("--repo=".length)
        continue
      }
      if (valueOpts.has(token)) cursor += 1
      continue
    }
    operand ??= token
  }
  return repoOverride === undefined ? { operand } : { repoOverride }
}

function gitSubcommand(tokens: string[], gitIndex: number): { command?: string; index: number } {
  let index = gitIndex + 1
  while (index < tokens.length) {
    const token = tokens[index]!
    if (token === "-C" || token === "-c" || token === "--git-dir" || token === "--work-tree") {
      index += 2
      continue
    }
    if (token.startsWith("-")) {
      index += 1
      continue
    }
    return { command: token, index }
  }
  return { index }
}

function positionalAfter(tokens: string[], index: number): string[] {
  const values: string[] = []
  let afterSeparator = false
  for (let cursor = index + 1; cursor < tokens.length; cursor += 1) {
    const token = tokens[cursor]!
    if (token === "--") {
      afterSeparator = true
      continue
    }
    if (!afterSeparator && token.startsWith("-")) continue
    values.push(token)
  }
  return values
}

function gitExecutionDirectory(
  tokens: string[],
  gitIndex: number,
  subcommandIndex: number,
  initialDirectory: string | undefined,
  prefix: string[],
): { directory?: string; reason?: string } {
  if (!initialDirectory) return { reason: "working directory before Git is unresolved" }
  if (prefix.some((token) => /^GIT_(?:DIR|WORK_TREE|COMMON_DIR|CONFIG[^=]*)=/.test(token)))
    return { reason: "Git repository or configuration environment overrides are unresolved" }
  let directory = initialDirectory
  for (let index = gitIndex + 1; index < subcommandIndex; index += 1) {
    const token = tokens[index]!
    if (
      token.startsWith("--git-dir") ||
      token.startsWith("--work-tree") ||
      token.startsWith("--config-env")
    )
      return { reason: "Git repository or configuration overrides are unresolved" }
    const config =
      token === "-c" ? tokens[index + 1] : token.startsWith("-c") ? token.slice(2) : undefined
    if (
      config &&
      /^(?:remote\.|url\.|branch\..*\.(?:remote|pushRemote)=|core\.worktree=)/i.test(config)
    )
      return { reason: "Git destination or worktree configuration overrides are unresolved" }
    let target: string | undefined
    if (token === "-C") {
      target = tokens[index + 1]
      index += 1
    } else if (token.startsWith("-C") && token.length > 2) {
      target = token.slice(2)
    }
    if (target === undefined) continue
    if (/[$`*?{}<>]/.test(target)) return { reason: "git -C contains unresolved shell expansion" }
    directory = resolveCommandPath(directory, target)
  }
  return { directory }
}

function plannedActions(command: string, directory: string): PlannedGitActions {
  const result: PlannedGitActions = {
    relevant: false,
    commit: false,
    plannedAdd: [],
    discardTargets: [],
    removeTargets: [],
    commands: [],
    rewriteBases: [],
    remoteCandidates: [],
    needsDefaultRemote: [],
  }
  const executionDirectories = new Set<string>()
  const directoryReasons = new Set<string>()

  for (const segment of shellCommandSegmentsWithDirectory(command, directory)) {
    const local = localExecutableCommand(segment.tokens)
    if (!local || basename(local.tokens[0] ?? "") !== "git") continue
    const tokens = local.tokens
    const gitIndex = 0
    const { command: subcommand, index } = gitSubcommand(tokens, gitIndex)
    if (!subcommand) continue
    if (
      ![
        "add",
        "commit",
        "checkout",
        "restore",
        "rm",
        "merge",
        "rebase",
        "stash",
        ...GIT_REMOTE_COMMANDS,
      ].includes(subcommand)
    )
      continue
    const execution = gitExecutionDirectory(
      tokens,
      gitIndex,
      index,
      segment.directory,
      local.prefix,
    )
    if (execution.directory) executionDirectories.add(execution.directory)
    else
      directoryReasons.add(
        execution.reason ?? segment.directoryReason ?? "Git directory is unresolved",
      )
    result.relevant = true
    result.commands.push(subcommand)
    if (subcommand === "rebase") {
      const args = tokens.slice(index + 1)
      const bases: string[] = []
      for (let cursor = 0; cursor < args.length; cursor++) {
        const arg = args[cursor]!
        if (
          ["--onto", "--exec", "-x", "--strategy", "-s", "--strategy-option", "-X"].includes(arg)
        ) {
          cursor++
          continue
        }
        if (!arg.startsWith("-")) {
          bases.push(arg)
        }
      }
      if (!args.includes("--root") && bases.length === 1 && !/[$`*?{}<>]/.test(bases[0]!))
        result.rewriteBases.push(bases[0]!)
    }
    if (subcommand === "commit") result.commit = true
    if (subcommand === "add") result.plannedAdd.push(...positionalAfter(tokens, index))
    if (subcommand === "rm") result.removeTargets.push(...positionalAfter(tokens, index))
    if (subcommand === "checkout" || subcommand === "restore") {
      const separator = tokens.indexOf("--", index + 1)
      if (separator >= 0) result.discardTargets.push(...tokens.slice(separator + 1))
    }
    if (
      subcommand === "push" ||
      subcommand === "fetch" ||
      subcommand === "pull" ||
      subcommand === "ls-remote"
    ) {
      const { operand, repoOverride } = networkOperand(tokens, index, subcommand)
      const candidates: string[] = []
      if (repoOverride !== undefined) candidates.push(repoOverride)
      if (operand !== undefined) candidates.push(operand)
      if (candidates.length > 0) {
        for (const candidate of candidates) {
          if (result.remoteCandidates.length < 8) result.remoteCandidates.push(candidate)
        }
      } else if (result.needsDefaultRemote.length < 4) {
        // --all fetches every configured remote, not just the default.
        const all = (subcommand === "fetch" || subcommand === "pull") && tokens.includes("--all")
        result.needsDefaultRemote.push(all ? `${subcommand} --all` : subcommand)
      }
    }
    if (subcommand === "remote") {
      const verbs = positionalAfter(tokens, index)
      const [verb, name, url] = verbs
      if (verb === "update") {
        // `remote update` fetches every configured remote (or the group's
        // members) when no group operand is given.
        if (name === undefined && result.needsDefaultRemote.length < 4) {
          result.needsDefaultRemote.push("remote update --all")
        }
      } else if (verb !== undefined && REMOTE_VERBS_WITH_NAME.has(verb)) {
        if (name !== undefined && result.remoteCandidates.length < 8)
          result.remoteCandidates.push(name)
        // set-url rewrites where the remote points: the new URL is a
        // destination fact, not just a name.
        if (verb === "set-url" && url !== undefined && result.remoteCandidates.length < 8) {
          result.remoteCandidates.push(url)
        }
      }
    }
  }
  if (executionDirectories.size === 1 && directoryReasons.size === 0) {
    result.executionDirectory = [...executionDirectories][0]!
  } else if (executionDirectories.size > 1) {
    result.directoryReason = "compound command targets multiple Git working directories"
  } else if (directoryReasons.size > 0) {
    result.directoryReason = [...directoryReasons].join("; ")
  }
  return result
}

function boundedList(values: string[], max = 200): { values: string[]; omitted: number } {
  return {
    values: values.slice(0, max),
    omitted: Math.max(0, values.length - max),
  }
}

/** Git inspection must never execute repository-configured extensions before
 *  the permission decision. Conversion filters (`clean`/`smudge`/`process`)
 *  and diff `textconv` drivers are shell commands from git config; disabling
 *  hooks, fsmonitor, and external diff is not enough because `git status` and
 *  `git diff` can invoke them on content comparison. Enumerate the configured
 *  keys (pure config reading, executes nothing) and override every one with a
 *  no-op so the evidence snapshot cannot run repo code.
 *
 *  The scan uses NUL-delimited output (`git config -z --get-regexp`), where
 *  each record is `key\nvalue\0`: splitting lines on whitespace would
 *  mis-parse legal subsections containing spaces (`[filter "a b"]`) and
 *  silently leave them active. Names containing `=` cannot be expressed
 *  through `-c KEY=VALUE` overrides (the override splits on the first `=`),
 *  so such a name fails the scan instead of being partially neutralized.
 *
 *  Only the in-flight subprocess is shared per directory: concurrent snapshots
 *  reuse one scan so burst evidence collection does not multiply git
 *  processes, but the result is never reused across time — a repository whose
 *  config changed since the last verified scan must be re-verified, not
 *  inspected on stale assurance. A failed or over-limit scan fails closed: if
 *  the whole relevant config cannot be proven neutralized, the snapshot is
 *  withheld rather than risk running repo code. */
const MAX_NEUTRALIZED_FILTERS = 50
const MAX_NEUTRALIZED_DIFF_DRIVERS = 50
const inFlightFilterScans = new Map<string, Promise<string[]>>()

/** Filter/driver names may themselves contain dots (`filter.a.b.clean`), so
 *  keys are matched structurally (strip the section and the trailing property)
 *  instead of with a dot-free capture group. Names may also contain spaces
 *  (`[filter "a b"]` is legal and overridable via `-c`), so keys are parsed
 *  from NUL-delimited scan output, never by splitting on whitespace. */
export function collectConversionKeys(stdout: string): {
  filterNames: Set<string>
  diffDrivers: Set<string>
} {
  const filterNames = new Set<string>()
  const diffDrivers = new Set<string>()
  const filterProps = [".clean", ".smudge", ".process", ".required"]
  // `git config -z --get-regexp` emits one `key\nvalue\0` record per match;
  // the key is everything before the first newline, whatever it contains.
  for (const record of stdout.split("\0")) {
    if (record.length === 0) continue
    const newline = record.indexOf("\n")
    const key = newline < 0 ? record : record.slice(0, newline)
    if (key.length === 0) continue
    if (key.startsWith("filter.")) {
      const prop = filterProps.find((suffix) => key.endsWith(suffix))
      if (prop === undefined) continue
      const name = key.slice("filter.".length, key.length - prop.length)
      if (name.length > 0) filterNames.add(name)
      continue
    }
    if (key.startsWith("diff.") && key.endsWith(".textconv")) {
      const driver = key.slice("diff.".length, key.length - ".textconv".length)
      if (driver.length > 0) diffDrivers.add(driver)
    }
  }
  return { filterNames, diffDrivers }
}

/** Build the `-c` overrides that neutralize every collected filter and diff
 *  driver. A name containing `=` cannot be expressed as a `-c KEY=VALUE`
 *  override (the override splits on the first `=` and would arm the wrong
 *  key), so it throws and the caller withholds the snapshot instead. */
export function conversionNeutralizationArgs(
  filterNames: Set<string>,
  diffDrivers: Set<string>,
): string[] {
  for (const name of filterNames) {
    if (name.includes("=")) {
      throw new Error(
        `repository configures conversion filter "${name}" which cannot be neutralized with a config override; refusing to inspect`,
      )
    }
  }
  for (const driver of diffDrivers) {
    if (driver.includes("=")) {
      throw new Error(
        `repository configures diff textconv driver "${driver}" which cannot be neutralized with a config override; refusing to inspect`,
      )
    }
  }
  const args: string[] = []
  for (const name of filterNames) {
    args.push(
      "-c",
      `filter.${name}.clean=cat`,
      "-c",
      `filter.${name}.smudge=cat`,
      "-c",
      `filter.${name}.process=`,
      "-c",
      `filter.${name}.required=false`,
    )
  }
  for (const driver of diffDrivers) {
    args.push("-c", `diff.${driver}.textconv=`)
  }
  return args
}

function filterNeutralizationArgs(directory: string): Promise<string[]> {
  const existing = inFlightFilterScans.get(directory)
  if (existing !== undefined) return existing
  const scan = (async () => {
    try {
      const result = await execFileAsync(
        "git",
        ["config", "-z", "--get-regexp", "^(filter|diff)\\."],
        {
          cwd: directory,
          timeout: 5_000,
          maxBuffer: 64 * 1024,
          encoding: "utf8",
          env: gitInspectionEnv(),
        },
      )
      const { filterNames, diffDrivers } = collectConversionKeys(result.stdout)
      if (filterNames.size > MAX_NEUTRALIZED_FILTERS) {
        // A resource limit must never degrade into "inspect while leaving the
        // remainder active": refuse the inspection instead.
        throw new Error(
          `repository configures ${filterNames.size} conversion filters (limit ${MAX_NEUTRALIZED_FILTERS}); refusing to inspect`,
        )
      }
      if (diffDrivers.size > MAX_NEUTRALIZED_DIFF_DRIVERS) {
        throw new Error(
          `repository configures ${diffDrivers.size} diff textconv drivers (limit ${MAX_NEUTRALIZED_DIFF_DRIVERS}); refusing to inspect`,
        )
      }
      const args = conversionNeutralizationArgs(filterNames, diffDrivers)
      return args
    } catch (error) {
      const record = error as { code?: unknown }
      // git config exits 1 when nothing matches: the common, benign case.
      if (record.code === 1) return []
      // Surface scan failures so the caller fails closed instead of
      // inspecting unverified.
      throw error instanceof Error ? error : new Error(String(error))
    } finally {
      inFlightFilterScans.delete(directory)
    }
  })()
  inFlightFilterScans.set(directory, scan)
  return scan
}

function gitInspectionEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    // Skip the system gitconfig too: it can define filters just like the
    // repository-local config can.
    GIT_CONFIG_NOSYSTEM: "1",
  }
}

/** A remote operand can be a configured remote name, a literal URL, an
 *  SCP-like `user@host:path` target, or a local path. Only syntactic
 *  classification happens here; configured names are resolved to URLs later,
 *  inside the containment envelope. */
function remoteOperandKind(value: string): "literal" | "name" {
  if (value.includes("://")) return "literal"
  if (value.startsWith("/")) return "literal"
  // SCP-like user@host:path: a colon before any slash with a user@host pair
  // before it. A plain "branch:ref" refspec has no "@", so it stays a name
  // and is later reported as unmatched by the configured-remote list.
  const colon = value.indexOf(":")
  if (colon > 0 && /^[^/@\s]+@[^/@\s]+$/.test(value.slice(0, colon))) return "literal"
  return "name"
}

/** Remote URLs may embed credential userinfo, including a token in the username
 *  slot with no password. None of it belongs in reviewer evidence. SCP-style
 *  `git@host:path` values have no scheme and stay untouched. */
function sanitizeRemoteUrl(url: string): string {
  // Redact before bounding: truncating first can remove the closing @ and
  // leave a credential prefix that no longer matches the userinfo pattern.
  return url
    .replace(/([a-z][a-z0-9+.-]*:\/\/)([^\s/@]+)(?::[^\s/@]*)?@/gi, "$1<redacted>@")
    .slice(0, 500)
}

interface RemoteTargetRecord {
  input: string
  kind: "configured-remote" | "literal" | "unmatched"
  url?: string | undefined
  pushUrls?: string[] | undefined
  fetchUrl?: string | undefined
  note?: string | undefined
  configuredMatches?: Array<{ name: string; push: boolean; fetch: boolean }>
}

/** Equate only documented GitHub transports; other destinations require exact URLs. */
function repositoryIdentity(value: string): string | undefined {
  if (value.length >= 200 || /[%\\]|(?:^|\/)\.{1,2}(?:\/|$)/.test(value)) return
  const scp = value.match(/^git@github\.com:([^\s?#]+)$/i)
  let path = scp?.[1]
  if (path === undefined) {
    try {
      const url = new URL(value)
      if (url.hostname.toLowerCase() !== "github.com") return `exact:${value}`
      if (url.search || url.hash) return
      if (
        !(url.protocol === "https:" && (url.port === "" || url.port === "443")) &&
        !(
          url.protocol === "ssh:" &&
          url.username === "git" &&
          (url.port === "" || url.port === "22")
        )
      )
        return
      path = url.pathname.replace(/^\//, "")
    } catch {
      return `exact:${value}`
    }
  }
  const normalized = path
    .replace(/\/$/, "")
    .replace(/\.git$/i, "")
    .toLowerCase()
  return /^[a-z0-9._-]+\/[a-z0-9._-]+$/.test(normalized) ? `github:${normalized}` : undefined
}

interface DefaultRemoteRecord {
  source:
    | "branch pushRemote"
    | "remote.pushDefault"
    | "branch remote"
    | "origin fallback"
    | "all configured remotes"
    | "unresolved"
  name?: string | undefined
  pushUrls?: string[] | undefined
  fetchUrl?: string | undefined
  note?: string | undefined
}

/** Resolve the collected remote operands against the repository's configured
 *  remotes, all through the neutralized, contained git runner. Every
 *  resolution failure stays a visible fact, never an invention. */
const MAX_RESOLVED_REMOTES = 5
const MAX_PUSH_URLS = 5

/** Push affects every configured pushurl (or every url when no pushurl
 *  exists), so resolution uses `get-url --push --all`: reporting only the
 *  first URL would hide a real destination. Fetch contacts only the first
 *  URL. Failures and empty output become notes, not silent absence. */
async function resolveConfiguredRemote(
  directory: string,
  name: string,
  neutralization: string[],
): Promise<{ pushUrls?: string[]; fetchUrl?: string | undefined; note?: string }> {
  const push = await runGit(
    directory,
    ["remote", "get-url", "--push", "--all", name],
    neutralization,
  )
  const fetch = await runGit(directory, ["remote", "get-url", name], neutralization)
  const pushUrls = push.ok
    ? push.stdout
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 0)
        .slice(0, MAX_PUSH_URLS)
        .map(sanitizeRemoteUrl)
    : undefined
  const fetchUrl =
    fetch.ok && fetch.stdout.trim() ? sanitizeRemoteUrl(fetch.stdout.trim()) : undefined
  const note =
    pushUrls === undefined && fetchUrl === undefined
      ? "URL resolution failed for this remote"
      : pushUrls === undefined
        ? "push URL resolution failed"
        : fetchUrl === undefined
          ? "fetch URL resolution failed"
          : undefined
  return {
    ...(pushUrls !== undefined ? { pushUrls } : {}),
    ...(fetchUrl !== undefined ? { fetchUrl } : {}),
    ...(note !== undefined ? { note } : {}),
  }
}

async function literalUrlRewrites(directory: string, neutralization: string[]) {
  const config = await runGit(directory, ["config", "--null", "--list"], neutralization)
  if (!config.ok) return undefined
  const rewrites: Array<{ base: string; prefix: string; push: boolean }> = []
  for (const entry of config.stdout.split("\0")) {
    const separator = entry.indexOf("\n")
    const key = entry.slice(0, separator)
    const match = key.match(/^url\.(.+)\.(pushinsteadof|insteadof)$/i)
    if (match)
      rewrites.push({
        base: match[1]!,
        prefix: entry.slice(separator + 1),
        push: match[2]!.toLowerCase() === "pushinsteadof",
      })
  }
  return rewrites
}

function expandLiteralUrl(
  input: string,
  rewrites: NonNullable<Awaited<ReturnType<typeof literalUrlRewrites>>>,
  push: boolean,
) {
  const match = (pushOnly: boolean) => {
    const matches = rewrites
      .filter((rewrite) => rewrite.push === pushOnly && input.startsWith(rewrite.prefix))
      .sort((a, b) => b.prefix.length - a.prefix.length)
    if (
      matches.some(
        (candidate) =>
          candidate.prefix.length === matches[0]?.prefix.length &&
          candidate.base !== matches[0]?.base,
      )
    )
      return "ambiguous" as const
    return matches[0]
  }
  const rewrite = (push ? match(true) : undefined) ?? match(false)
  if (rewrite === "ambiguous") return undefined
  return rewrite ? rewrite.base + input.slice(rewrite.prefix.length) : input
}

async function resolveRemoteTargets(
  directory: string,
  planned: PlannedGitActions,
  configuredNames: string[],
  neutralization: string[],
): Promise<{ targets: RemoteTargetRecord[]; omitted: number; defaults: DefaultRemoteRecord[] }> {
  const targets: RemoteTargetRecord[] = []
  const seen = new Set<string>()
  // Resolution is memoized per remote: repeated operands and default-remote
  // fallbacks reuse one lookup instead of re-running git.
  const resolvedRemotes = new Map<string, Awaited<ReturnType<typeof resolveConfiguredRemote>>>()
  const rewrites = planned.remoteCandidates.some((input) => remoteOperandKind(input) === "literal")
    ? await literalUrlRewrites(directory, neutralization)
    : undefined
  const resolveRemote = async (name: string) => {
    if (!resolvedRemotes.has(name)) {
      resolvedRemotes.set(name, await resolveConfiguredRemote(directory, name, neutralization))
    }
    return resolvedRemotes.get(name)!
  }
  for (const input of planned.remoteCandidates) {
    if (targets.length >= MAX_RESOLVED_REMOTES) break
    if (seen.has(input)) continue
    seen.add(input)
    // Every recorded operand is bounded and redacted: names get the length
    // cap, literals additionally lose credential userinfo.
    const bounded = sanitizeRemoteUrl(input).slice(0, 200)
    if (remoteOperandKind(input) === "literal") {
      const identity = repositoryIdentity(input)
      // Literal destinations have no configured pushurl. Apply the longest
      // matching rewrite separately for fetch and push, without contacting it.
      const pushUrl = rewrites === undefined ? undefined : expandLiteralUrl(input, rewrites, true)
      const fetchUrl = rewrites === undefined ? undefined : expandLiteralUrl(input, rewrites, false)
      const literal = {
        ...(pushUrl === undefined ? {} : { pushUrls: [sanitizeRemoteUrl(pushUrl)] }),
        ...(fetchUrl === undefined ? {} : { fetchUrl: sanitizeRemoteUrl(fetchUrl) }),
        ...(pushUrl === undefined || fetchUrl === undefined
          ? { note: "literal URL rewrite configuration is unavailable or ambiguous" }
          : {}),
      }
      const pushIdentity =
        identity !== undefined && literal.pushUrls?.length === 1
          ? repositoryIdentity(literal.pushUrls[0]!)
          : undefined
      const fetchIdentity =
        identity !== undefined && literal.fetchUrl !== undefined
          ? repositoryIdentity(literal.fetchUrl)
          : undefined
      const matches =
        pushIdentity === undefined && fetchIdentity === undefined
          ? []
          : (
              await Promise.all(
                configuredNames.slice(0, MAX_RESOLVED_REMOTES).map(async (name) => {
                  const urls = await resolveRemote(name)
                  return {
                    name,
                    push:
                      pushIdentity !== undefined &&
                      (urls.pushUrls?.some((url) => repositoryIdentity(url) === pushIdentity) ??
                        false),
                    fetch:
                      fetchIdentity !== undefined &&
                      urls.fetchUrl !== undefined &&
                      repositoryIdentity(urls.fetchUrl) === fetchIdentity,
                  }
                }),
              )
            ).filter((match) => match.push || match.fetch)
      targets.push({
        input: bounded,
        kind: "literal",
        url: bounded,
        ...literal,
        ...(matches.length === 0
          ? {}
          : {
              configuredMatches: matches,
              note: `${literal.note ? `${literal.note}; ` : ""}repository identity matches configured URLs only for the marked push/fetch roles; this does not establish authorization or destination trust`,
            }),
      })
      continue
    }
    if (configuredNames.includes(input)) {
      const urls = await resolveRemote(input)
      targets.push({ input: bounded, kind: "configured-remote", ...urls })
      continue
    }
    targets.push({
      input: bounded,
      kind: "unmatched",
      note: "matches no configured remote; git treats the operand as a direct repository URL or path (the command fails unless that target exists)",
    })
  }

  const defaults: DefaultRemoteRecord[] = []
  for (const annotation of planned.needsDefaultRemote) {
    if (annotation.includes("--all")) {
      defaults.push({
        source: "all configured remotes",
        note: `${annotation} contacts every configured remote: ${configuredNames.slice(0, 10).join(", ") || "(none configured)"}`,
      })
      continue
    }
    defaults.push(
      await resolveDefaultRemote(
        directory,
        annotation,
        configuredNames,
        neutralization,
        resolveRemote,
      ),
    )
  }

  return {
    targets,
    // Unique candidates beyond the resolution cap, including the one that
    // tripped it: the earlier `seen`-based count missed exactly that one.
    omitted: Math.max(0, new Set(planned.remoteCandidates).size - targets.length),
    defaults,
  }
}

/** Resolve which remote a no-operand network subcommand contacts, following
 *  git's own precedence: push consults branch.<name>.pushRemote, then
 *  remote.pushDefault, then branch.<name>.remote; fetch/pull consult
 *  branch.<name>.remote; both fall back to origin when configured. The
 *  configured value may itself be a URL rather than a remote name, so it is
 *  bounded and redacted like any operand. */
async function resolveDefaultRemote(
  directory: string,
  annotation: string,
  configuredNames: string[],
  neutralization: string[],
  resolveRemote: (name: string) => Promise<Awaited<ReturnType<typeof resolveConfiguredRemote>>>,
): Promise<DefaultRemoteRecord> {
  const branch = await runGit(directory, ["rev-parse", "--abbrev-ref", "HEAD"], neutralization)
  if (!branch.ok) {
    return { source: "unresolved", note: "current branch could not be resolved" }
  }
  const branchName = branch.stdout.trim()
  const configChain =
    annotation === "push"
      ? [
          { key: `branch.${branchName}.pushRemote`, source: "branch pushRemote" as const },
          { key: "remote.pushDefault", source: "remote.pushDefault" as const },
          { key: `branch.${branchName}.remote`, source: "branch remote" as const },
        ]
      : [{ key: `branch.${branchName}.remote`, source: "branch remote" as const }]
  for (const step of configChain) {
    const value = await runGit(directory, ["config", "--get", step.key], neutralization)
    if (!value.ok || !value.stdout.trim()) continue
    const rawName = value.stdout.trim()
    const name = sanitizeRemoteUrl(rawName).slice(0, 200)
    if (!configuredNames.includes(rawName)) {
      // branch.*.remote may legitimately hold a URL or path instead of a
      // configured remote name: report it as the destination verbatim
      // (bounded) instead of resolving it as a name.
      return { source: step.source, name, note: "configured value is not a named remote" }
    }
    const urls = await resolveRemote(rawName)
    return { source: step.source, name, ...urls }
  }
  if (configuredNames.includes("origin")) {
    const urls = await resolveRemote("origin")
    return { source: "origin fallback", name: "origin", ...urls }
  }
  return {
    source: "unresolved",
    note: `no branch.${branchName}.remote, no remote.pushDefault, and no origin remote is configured`,
  }
}

async function runGit(
  directory: string,
  args: string[],
  neutralization: string[] = [],
): Promise<{ ok: true; stdout: string } | { ok: false; reason: string }> {
  try {
    const result = await execFileAsync(
      "git",
      ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", ...neutralization, ...args],
      {
        cwd: directory,
        timeout: 2_000,
        maxBuffer: 512 * 1024,
        encoding: "utf8",
        env: gitInspectionEnv(),
      },
    )
    return { ok: true, stdout: result.stdout }
  } catch (error) {
    const record = error as {
      code?: unknown
      signal?: unknown
      stderr?: unknown
      message?: unknown
    }
    const reason =
      typeof record.stderr === "string" && record.stderr.trim()
        ? record.stderr.trim()
        : typeof record.message === "string"
          ? record.message
          : String(error)
    return { ok: false, reason: reason.slice(0, 1_000) }
  }
}

function parseStatus(stdout: string): {
  branch: string
  staged: string[]
  unstaged: string[]
  untracked: string[]
  unmerged: string[]
} {
  const lines = stdout.split(/\r?\n/).filter(Boolean)
  const branchLine = lines.find((line) => line.startsWith("## "))
  const branch = branchLine?.slice(3).split("...")[0]?.trim() || "<detached-or-unknown>"
  const staged: string[] = []
  const unstaged: string[] = []
  const untracked: string[] = []
  const unmerged: string[] = []
  for (const line of lines) {
    if (line.startsWith("## ")) continue
    const x = line[0] ?? " "
    const y = line[1] ?? " "
    const path = line.slice(3)
    if (x === "?" && y === "?") {
      untracked.push(path)
      continue
    }
    if (["DD", "AU", "UD", "UA", "DU", "AA", "UU"].includes(x + y)) {
      unmerged.push(path)
      continue
    }
    if (x !== " ") staged.push(path)
    if (y !== " ") unstaged.push(path)
  }
  return { branch, staged, unstaged, untracked, unmerged }
}

async function rewriteEvidence(
  directory: string,
  planned: PlannedGitActions,
  neutralization: string[],
) {
  if (!planned.commands.includes("rebase")) return undefined
  const base = planned.rewriteBases[0]
  if (base === undefined || planned.rewriteBases.length !== 1)
    return { status: "unavailable", reason: "rebase range is not a single literal base" }
  const resolved = await runGit(
    directory,
    ["rev-parse", "--verify", "--end-of-options", `${base}^{commit}`],
    neutralization,
  )
  if (!resolved.ok) return { status: "unavailable", reason: "rebase base could not be resolved" }
  const sha = resolved.stdout.trim()
  if (!/^[a-f0-9]{40,64}$/.test(sha))
    return { status: "unavailable", reason: "rebase base is not a commit" }
  const range = `${sha}..HEAD`
  const [total, local, refs, head, upstream] = await Promise.all([
    runGit(directory, ["rev-list", "--count", range], neutralization),
    runGit(directory, ["rev-list", "--count", range, "--not", "--remotes"], neutralization),
    runGit(directory, ["for-each-ref", "--format=%(refname)", "refs/remotes"], neutralization),
    runGit(directory, ["rev-parse", "HEAD"], neutralization),
    runGit(directory, ["rev-parse", "--symbolic-full-name", "@{upstream}"], neutralization),
  ])
  if (!total.ok || !local.ok || !refs.ok || !head.ok)
    return {
      status: "unavailable",
      reason: "rewrite range or remote-tracking state could not be inspected",
    }
  const totalCount = Number(total.stdout.trim())
  const localCount = Number(local.stdout.trim())
  return {
    status: "available",
    base: sha,
    head: head.stdout.trim(),
    commitsInRange: totalCount,
    commitsAbsentFromRemoteTrackingRefs: localCount,
    commitsPresentInRemoteTrackingRefs: totalCount - localCount,
    remoteTrackingRefs: boundedList(refs.stdout.trim().split("\n").filter(Boolean), 20),
    ...(upstream.ok ? { upstream: upstream.stdout.trim() } : {}),
    note: "read-only local snapshot; remote-tracking refs may be stale and absence is not proof of unpublished history",
  }
}

function unresolved(values: string[]): string[] {
  return values.filter((value) => /[$`*?{}<>]/.test(value))
}

export async function enrichGitEvidence(
  request: PermissionRequest,
  directory: string,
  maxChars: number,
  worktree?: string,
): Promise<GitEnrichmentResult> {
  if (request.permission !== "bash") return { text: "" }
  const command = sourceCommand(request)
  const planned = plannedActions(command, directory)
  if (!planned.relevant) return { text: "" }
  const publicPlanned = {
    ...planned,
    remoteCandidates: planned.remoteCandidates.map(sanitizeRemoteUrl),
  }
  if (!planned.executionDirectory) {
    return {
      text: `GIT_STATE_ANALYSIS\n${JSON.stringify(
        {
          status: "unavailable",
          reason: planned.directoryReason ?? "Git directory is unresolved",
          planned: publicPlanned,
        },
        null,
        2,
      ).slice(0, maxChars)}`,
    }
  }

  // The planned directory comes from the reviewed command itself (`cd`,
  // `git -C`), so it can never mint an inspection root. Git runs subprocesses
  // with that directory as cwd; without containment a `cd /other/repo &&`
  // prefix would inspect an unrelated repository. Only the session directory,
  // the worktree, and /tmp/opencode may be inspected, judged on real paths so
  // symlinks cannot bridge out. An unresolvable planned directory is treated
  // as outside: there is nothing to inspect that the review can vouch for.
  const plannedDirectory = planned.executionDirectory
  const realPlannedDirectory = await realpath(plannedDirectory).catch(() => undefined)
  const gitDirectory = realPlannedDirectory
  if (gitDirectory === undefined) {
    return {
      text: `GIT_STATE_ANALYSIS\n${JSON.stringify(
        {
          status: "unavailable",
          reason: "planned Git directory does not resolve to a real path",
          planned: publicPlanned,
        },
        null,
        2,
      ).slice(0, maxChars)}`,
    }
  }
  const roots = await approvedEvidenceRoots(directory, worktree)
  if (!roots.some((root) => isWithinRoot(gitDirectory, root))) {
    return {
      text: `GIT_STATE_ANALYSIS\n${JSON.stringify(
        {
          status: "unavailable",
          reason: "planned Git directory is outside approved enrichment roots",
          planned: publicPlanned,
        },
        null,
        2,
      ).slice(0, maxChars)}`,
    }
  }
  let neutralization: string[]
  try {
    neutralization = await filterNeutralizationArgs(gitDirectory)
  } catch (error) {
    // Fail closed: without a verified config we cannot prove the inspection
    // would not run repository-configured filters, so no snapshot is taken.
    const reason = `unable to verify git conversion filters before inspection (${error instanceof Error ? error.message : String(error)})`
    return {
      text: `GIT_STATE_ANALYSIS\n${JSON.stringify(
        { status: "unavailable", reason: reason.slice(0, 1_000), planned: publicPlanned },
        null,
        2,
      ).slice(0, maxChars)}`,
    }
  }

  // Resolve the repository root first and require it inside the approved
  // roots: git discovers repositories upward, so a working directory inside
  // an approved root can otherwise sit in a repository whose root, and whose
  // whole status/diff state, lies outside them. The window between this
  // realpath and the git subprocesses below cannot be eliminated (git takes
  // a path as cwd, not an open descriptor), but the reviewed command has not
  // run yet, so racing it requires a second concurrent process.
  const root = await runGit(gitDirectory, ["rev-parse", "--show-toplevel"], neutralization)
  if (!root.ok) {
    return {
      text: `GIT_STATE_ANALYSIS\n${JSON.stringify(
        { status: "unavailable", reason: root.reason, planned: publicPlanned },
        null,
        2,
      ).slice(0, maxChars)}`,
    }
  }
  const repositoryRoot = await realpath(root.stdout.trim()).catch(() => undefined)
  if (repositoryRoot === undefined || !roots.some((r) => isWithinRoot(repositoryRoot, r))) {
    return {
      text: `GIT_STATE_ANALYSIS\n${JSON.stringify(
        {
          status: "unavailable",
          reason: "repository root is outside approved enrichment roots",
          planned: publicPlanned,
        },
        null,
        2,
      ).slice(0, maxChars)}`,
    }
  }

  const status = await runGit(
    gitDirectory,
    ["status", "--porcelain=v1", "--branch", "--untracked-files=normal"],
    neutralization,
  )
  if (!status.ok || !/^## [^\r\n]+\r?\n/.test(status.stdout)) {
    return {
      text: `GIT_STATE_ANALYSIS\n${JSON.stringify(
        {
          status: "unavailable",
          reason: status.ok
            ? "Git status output is incomplete: missing branch header"
            : status.reason,
          planned: publicPlanned,
        },
        null,
        2,
      ).slice(0, maxChars)}`,
    }
  }

  const parsed = parseStatus(status.stdout)
  const [mergeHead, rewrite] = await Promise.all([
    planned.commands.some((cmd) => ["add", "commit", "merge"].includes(cmd))
      ? runGit(gitDirectory, ["rev-parse", "--verify", "--quiet", "MERGE_HEAD"], neutralization)
      : undefined,
    rewriteEvidence(gitDirectory, planned, neutralization),
  ])
  // Remote operands only resolve inside the containment envelope, after the
  // repository root has been verified: `git remote`/`get-url` are plain config
  // reads, but running them anywhere would inspect an arbitrary repository.
  // The listing is gated on actual demand so plain add/commit reviews spawn
  // no extra git processes.
  const needsRemoteEvidence =
    planned.remoteCandidates.length > 0 || planned.needsDefaultRemote.length > 0
  const remotes = needsRemoteEvidence
    ? await runGit(gitDirectory, ["remote"], neutralization)
    : undefined
  const configuredNames = remotes?.ok
    ? remotes.stdout
        .split(/\s+/)
        .filter((name) => name.length > 0)
        .slice(0, 50)
    : []
  const remoteResolution = !needsRemoteEvidence
    ? undefined
    : remotes?.ok
      ? await resolveRemoteTargets(gitDirectory, planned, configuredNames, neutralization)
      : {
          targets: [],
          omitted: 0,
          defaults: [
            {
              source: "unresolved",
              note: `configured remote listing failed: ${(remotes && !remotes.ok ? remotes.reason : "unknown").slice(0, 200)}`,
            } satisfies DefaultRemoteRecord,
          ],
        }
  const affectedTargets = [
    ...new Set([...planned.discardTargets, ...planned.removeTargets]),
  ].filter((value) => !/[$`*?{}<>]/.test(value))
  const targetDiff =
    affectedTargets.length === 0
      ? undefined
      : await runGit(
          gitDirectory,
          ["diff", "--numstat", "--no-ext-diff", "--", ...affectedTargets],
          neutralization,
        )

  const record = {
    status: "available",
    repositoryRoot: root.stdout.trim(),
    branch: parsed.branch,
    plannedCommands: planned.commands,
    commitRequested: planned.commit,
    plannedAdd: boundedList(planned.plannedAdd),
    preexistingStaged: boundedList(parsed.staged),
    ...(mergeHead?.ok
      ? {
          indexContext: "merge-result-index",
          mergeHead: mergeHead.stdout.trim(),
          note: "the current index includes the in-progress merge result; this does not establish ownership or approval of every staged change",
        }
      : {}),
    ...(parsed.unmerged.length > 0 ? { unmerged: boundedList(parsed.unmerged) } : {}),
    ...(rewrite === undefined ? {} : { rewrite }),
    unstaged: boundedList(parsed.unstaged),
    untracked: boundedList(parsed.untracked),
    discardTargets: boundedList(planned.discardTargets),
    removeTargets: boundedList(planned.removeTargets),
    ...(remoteResolution === undefined
      ? {}
      : {
          remoteTargets: remoteResolution.targets,
          remoteTargetsOmitted: remoteResolution.omitted,
          defaultRemotes: remoteResolution.defaults,
          configuredRemotes: configuredNames,
        }),
    unresolvedPlannedPaths: boundedList(
      unresolved([...planned.plannedAdd, ...planned.discardTargets, ...planned.removeTargets]),
    ),
    ...(targetDiff === undefined
      ? {}
      : targetDiff.ok
        ? { affectedTargetNumstat: targetDiff.stdout.slice(0, 8_000) || "<no unstaged diff>" }
        : { affectedTargetNumstat: `<unavailable: ${targetDiff.reason}>` }),
  }
  const serialized = JSON.stringify(record, null, 2)
  const bounded =
    serialized.length <= maxChars
      ? serialized
      : `${serialized.slice(0, maxChars)}\n<git_enrichment_truncated characters="${serialized.length - maxChars}" />`
  return { text: `GIT_STATE_ANALYSIS\n${bounded}` }
}
