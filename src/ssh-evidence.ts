import { createHash } from "node:crypto"
import { constants as fsConstants } from "node:fs"
import { open, lstat, realpath, readlink } from "node:fs/promises"
import { basename, isAbsolute, resolve, sep } from "node:path"
import { isCommandAbsolute, resolveCommandPath } from "./shell-path.ts"
import type { PermissionRequest } from "./types.ts"
import { commandSegments, sshValueOption } from "./shell-lexer.ts"
import { sourceCommand } from "./evidence/source-command.ts"

const O_RDONLY = typeof fsConstants.O_RDONLY === "number" ? fsConstants.O_RDONLY : 0
const O_NOFOLLOW = typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0
const O_NONBLOCK = typeof fsConstants.O_NONBLOCK === "number" ? fsConstants.O_NONBLOCK : 0

export interface FileEvidence {
  source: "file"
  path: string
  status: "included" | "truncated" | "unavailable" | "blocked"
  reason?: string
  size?: number
  includedBytes?: number
  includedSha256?: string
  content?: string
}

export interface SshAuditSummary {
  destination: string
  port?: string
  remoteCommandSha256?: string
  stdinSource?: string
  stdinStatus?: string
  stdinReason?: string
}

export interface SshEnrichmentResult {
  text: string
  audit: SshAuditSummary[]
  preflightDenial?: string
}

const SENSITIVE_PATH =
  /(?:^|\/)(?:\.env(?:\.|$)|\.ssh(?:\/|$)|\.aws(?:\/|$)|\.config\/(?:gh|gcloud)(?:\/|$)|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$|credentials(?:\.json)?$|authorized_keys$|known_hosts$|\.npmrc$|\.pypirc$|\.netrc$)/i
const SENSITIVE_CONTENT =
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:sk|nvapi)-[A-Za-z0-9_-]{16,}|\b(?:ghp|gho|ghs|ghr|ghu)_[A-Za-z0-9_-]{16,}|\bgithub_pat_[A-Za-z0-9_-]{16,}|\b(?:api[_-]?key|access[_-]?token|password)\s*[:=]\s*["'][^"'\n]{8,}["']/i

function isSensitiveEvidencePath(value: string): boolean {
  return SENSITIVE_PATH.test(value.replaceAll("\\", "/"))
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex")
}

export function shellCommandSegments(
  command: string,
): Array<{ tokens: string[]; preceding?: string; endedBy?: string }> {
  return commandSegments(command).map((segment) => ({
    tokens: segment.tokens,
    ...(segment.preceding === undefined ? {} : { preceding: segment.preceding }),
    ...(segment.endedBy === undefined ? {} : { endedBy: segment.endedBy }),
  }))
}

export interface ShellCommandSegmentWithDirectory {
  tokens: string[]
  preceding?: string
  directory?: string
  directoryReason?: string
}

function cdTarget(
  tokens: string[],
  directory: string | undefined,
): { directory?: string; reason?: string } {
  if (tokens.length < 2 || commandName(tokens[0]!) !== "cd") return {}
  const values = tokens[1] === "--" ? tokens.slice(2) : tokens.slice(1)
  if (values.length !== 1) return { reason: "cd target is absent or ambiguous" }
  const target = values[0]!
  if (/[$`*?{}<>]/.test(target)) return { reason: "cd target contains unresolved shell expansion" }
  if (isCommandAbsolute(target)) return { directory: resolveCommandPath(target) }
  if (directory === undefined) {
    return { reason: "relative cd target follows an unresolved working directory" }
  }
  return { directory: resolveCommandPath(directory, target) }
}

export function shellCommandSegmentsWithDirectory(
  command: string,
  initialDirectory: string,
): ShellCommandSegmentWithDirectory[] {
  const segments = shellCommandSegments(command)
  const result: ShellCommandSegmentWithDirectory[] = []
  let directory: string | undefined = resolveCommandPath(initialDirectory)
  let directoryReason: string | undefined
  let pendingCd:
    { before?: string; beforeReason?: string; target?: string; reason?: string } | undefined
  // Parent states of open subshells, innermost last. A `cd` inside `( ... )`
  // only affects segments up to the matching `)`: the outer state resumes
  // after it, and a cd as the last subshell command never reaches the next
  // command. States, not just directories: an ambiguous parent stays
  // ambiguous after the group closes.
  const subshellStates: Array<{ directory?: string; reason?: string }> = []

  // Apply a pending `cd` according to the operator linking it to what
  // follows. `&&` guarantees the cd succeeded (its target applies, or its
  // unresolved reason); `||` means the next segment only runs after a
  // FAILURE, so the directory is still the pre-cd one; any other separator
  // (`;`, `|`, `&`, plain adjacency) leaves both outcomes live.
  const applyPendingCd = (operator: string | undefined) => {
    if (pendingCd === undefined) return
    if (operator === "&&") {
      if (pendingCd.target !== undefined) {
        directory = pendingCd.target
        directoryReason = undefined
      } else {
        directory = undefined
        directoryReason = pendingCd.reason ?? "preceding cd target is unresolved"
      }
    } else if (operator === "||") {
      directory = pendingCd.before
      directoryReason = pendingCd.beforeReason
    } else {
      directory = undefined
      directoryReason = "working directory after cd is conditional or ambiguous"
    }
    pendingCd = undefined
  }

  // A `(` opens a subshell that inherits the parent state at that moment.
  // The pushed restore point is that same post-cd parent state, so
  // `cd sub && ( … ) && cmd` resumes in sub, not in the pre-cd directory.
  const openSubshell = () => {
    if (pendingCd !== undefined) {
      // The cd sits immediately before the `(` with no operator between:
      // the group may start in either directory.
      directory = undefined
      directoryReason =
        "subshell follows cd without a success or failure operator; its working directory is ambiguous"
      pendingCd = undefined
    }
    subshellStates.push({
      ...(directory === undefined ? {} : { directory }),
      ...(directoryReason === undefined ? {} : { reason: directoryReason }),
    })
  }

  const closeSubshell = () => {
    const restore = subshellStates.pop()
    if (restore !== undefined) {
      directory = restore.directory
      directoryReason = restore.reason
    }
    pendingCd = undefined
  }

  for (const segment of segments) {
    applyPendingCd(segment.preceding)
    result.push({
      ...segment,
      ...(directory === undefined
        ? { directoryReason: directoryReason ?? "working directory is unresolved" }
        : { directory }),
    })
    if (segment.tokens.length === 0) {
      // Paren marker: a grouping event with no command of its own.
      if (segment.endedBy === "(") openSubshell()
      else if (segment.endedBy === ")") closeSubshell()
      continue
    }
    if (commandName(segment.tokens[0]!) === "cd") {
      const target = cdTarget(segment.tokens, directory)
      pendingCd = {
        ...(directory === undefined ? {} : { before: directory }),
        ...(directoryReason === undefined ? {} : { beforeReason: directoryReason }),
        ...(target.directory === undefined ? {} : { target: target.directory }),
        ...(target.reason === undefined ? {} : { reason: target.reason }),
      }
    }
    if (segment.endedBy === "(") openSubshell()
    else if (segment.endedBy === ")") closeSubshell()
  }
  return result
}

function commandName(value: string): string {
  return basename(value)
}

function findSshIndex(tokens: ReadonlyArray<string>): number {
  return tokens.findIndex((token) => commandName(token) === "ssh")
}

function parseSsh(
  tokens: ReadonlyArray<string>,
  sshIndex: number,
):
  | {
      destination: string
      host: string
      user?: string
      port?: string
      identityFile?: string
      strictHostKeyChecking?: string
      remoteCommand: string
    }
  | undefined {
  let destination: string | undefined
  let port: string | undefined
  let identityFile: string | undefined
  let strictHostKeyChecking: string | undefined
  let index = sshIndex + 1

  while (index < tokens.length) {
    const token = tokens[index]!
    if (token === "--") {
      index += 1
      destination = tokens[index]
      index += 1
      break
    }
    if (!token.startsWith("-") || token === "-") {
      destination = token
      index += 1
      break
    }

    const valued = sshValueOption(token)
    if (valued !== undefined) {
      const value = valued.attached ?? tokens[index + 1]
      if (valued.option === "-i") identityFile = value
      if (valued.option === "-p") port = value
      if (valued.option === "-o" && value) {
        const match = /^StrictHostKeyChecking=(.+)$/i.exec(value)
        if (match) strictHostKeyChecking = match[1]
      }
      index += valued.attached === undefined ? 2 : 1
    } else {
      index += 1
    }
  }

  if (!destination) return
  const at = destination.lastIndexOf("@")
  const user = at > 0 ? destination.slice(0, at) : undefined
  const host = at > 0 ? destination.slice(at + 1) : destination
  const remoteTokens = [...tokens.slice(index)]
  while (remoteTokens.length > 0 && /^\d*(?:>|<)/.test(remoteTokens.at(-1)!)) remoteTokens.pop()
  return {
    destination,
    host,
    ...(user === undefined ? {} : { user }),
    ...(port === undefined ? {} : { port }),
    ...(identityFile === undefined ? {} : { identityFile }),
    ...(strictHostKeyChecking === undefined ? {} : { strictHostKeyChecking }),
    remoteCommand: remoteTokens.join(" "),
  }
}

function catSource(tokens: ReadonlyArray<string>): string | undefined {
  if (tokens.length < 2 || commandName(tokens[0]!) !== "cat") return
  const positional = tokens.slice(1).filter((value) => value !== "--" && !value.startsWith("-"))
  if (positional.length !== 1) return
  const source = positional[0]!
  if (/[$`*?{}<>]/.test(source)) return
  return source
}

/** Whether `path` equals `root` or lives somewhere below it. */
export function isWithinRoot(path: string, root: string): boolean {
  return path === root || path.startsWith(`${root}${sep}`)
}

/** The only roots enrichment may read or inspect below: the session's
 *  initial directory, the workspace worktree, and the reviewer temp area.
 *  Directories tracked through a `cd` in the reviewed command are resolution
 *  bases, never roots: a command cannot mint the right to enrich from
 *  somewhere else. Roots are re-validated on every enrichment read, so a
 *  swapped path between two reads re-fails the check instead of widening
 *  scope mid-request. */
export async function approvedEvidenceRoots(
  rootDirectory: string,
  worktree?: string,
  temporaryPath: string = "/tmp/opencode",
): Promise<string[]> {
  const [directoryRoot, worktreeRoot, temporaryRoot] = await Promise.all([
    realpath(rootDirectory).catch(() => resolve(rootDirectory)),
    worktree === undefined ? undefined : realpath(worktree).catch(() => resolve(worktree)),
    temporaryEvidenceRoot(temporaryPath),
  ])
  return [
    directoryRoot,
    ...(worktreeRoot === undefined ? [] : [worktreeRoot]),
    ...(temporaryRoot === undefined ? [] : [temporaryRoot]),
  ]
}

/** The temp area qualifies as an evidence root only when it is exactly the
 *  directory it claims to be: a real directory (a symlink would quietly make
 *  whatever it points to readable), owned by the current user, and not
 *  group- or world-writable (anyone could otherwise plant or replace the
 *  files enrichment reads). Anything else, including absence, drops the
 *  root: enrichment simply cannot use it, which fails closed. */
async function temporaryEvidenceRoot(path: string): Promise<string | undefined> {
  try {
    const info = await lstat(path)
    if (info.isSymbolicLink() || !info.isDirectory()) return undefined
    if (typeof process.getuid === "function") {
      const uid = process.getuid()
      if (typeof info.uid === "number" && info.uid !== uid) return undefined
    }
    // Windows reports one mode for every directory, so the Unix
    // group/other-writable bit cannot identify a private temp root.
    if (process.platform !== "win32" && info.mode & 0o022) return undefined
    return path
  } catch {
    return undefined
  }
}

/** Best-effort Linux-only resolution of an open descriptor back to its real
 *  path (`/proc/self/fd/<n>`). Returns undefined where /proc is unavailable
 *  (non-Linux platforms, hardened containers): the caller then keeps the
 *  pre-open checks as the only line of defense, which is the documented
 *  limitation rather than a silent pass. */
async function descriptorRealPath(fd: number): Promise<string | undefined> {
  try {
    return await readlink(`/proc/self/fd/${fd}`)
  } catch {
    return undefined
  }
}

async function includeFileOnce(
  source: string,
  directory: string,
  rootDirectory: string,
  worktree: string,
  maxChars: number,
): Promise<FileEvidence> {
  // `directory` is only the RESOLUTION base: it may be a working directory
  // tracked across a `cd` in the very command under review, so it can never
  // mint approved read roots. Containment is judged against `rootDirectory`
  // (the session's initial directory), the worktree, and /tmp/opencode: a
  // `cd /outside && python x.py` resolves in /outside but stays blocked.
  const resolved = resolve(directory, source)
  if (isSensitiveEvidencePath(resolved)) {
    return { source: "file", path: resolved, status: "blocked", reason: "sensitive path" }
  }

  try {
    // Resolve the source independently so ENOENT can only mean that this
    // specific stdin file is missing, never that an auxiliary root vanished.
    const actual = await realpath(resolved)
    const roots = await approvedEvidenceRoots(rootDirectory, worktree)
    if (!roots.some((root) => isWithinRoot(actual, root))) {
      return {
        source: "file",
        path: resolved,
        status: "blocked",
        reason: "outside approved enrichment roots",
      }
    }
    if (isSensitiveEvidencePath(actual)) {
      return {
        source: "file",
        path: resolved,
        status: "blocked",
        reason: "sensitive resolved path",
      }
    }

    // Open first, then verify through the open descriptor (fstat): the checks
    // above judged a path, and the descriptor is the only thing guaranteed to
    // match what we actually read. O_NOFOLLOW (where available) rejects a
    // last-component symlink swapped in between realpath and open. O_NONBLOCK
    // keeps the open from BLOCKING on a FIFO with no writer — without it the
    // review would hang before fstat ever got the chance to reject the
    // non-regular file; on regular files the flag is a no-op.
    const limit = Math.max(1, maxChars)
    const handle = await open(actual, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
    try {
      const info = await handle.stat()
      if (!info.isFile()) {
        return {
          source: "file",
          path: resolved,
          status: "unavailable",
          reason: "not a regular file",
        }
      }
      // O_NOFOLLOW only guards the LAST path component. On Linux, resolve the
      // open descriptor back to its real path and re-run the containment and
      // sensitivity checks against what is actually being read: an
      // intermediate directory swapped for a symlink between the realpath
      // check and the open is then caught instead of silently reading outside
      // the approved roots.
      const fdPath = await descriptorRealPath(handle.fd)
      if (fdPath !== undefined) {
        if (!roots.some((root) => isWithinRoot(fdPath, root))) {
          return {
            source: "file",
            path: resolved,
            status: "blocked",
            reason: `open descriptor resolves outside approved enrichment roots (${fdPath})`,
          }
        }
        if (isSensitiveEvidencePath(fdPath)) {
          return {
            source: "file",
            path: resolved,
            status: "blocked",
            reason: "sensitive resolved path",
          }
        }
      }
      const buffer = Buffer.alloc(Math.min(info.size, limit + 1))
      // A single read is not guaranteed to fill the buffer, so loop until
      // full or EOF. A short total means the file shrank mid-read; the status
      // below then reports truncation instead of silently covering fewer
      // bytes than the size claims.
      let bytesRead = 0
      while (bytesRead < buffer.length) {
        const { bytesRead: count } = await handle.read(
          buffer,
          bytesRead,
          buffer.length - bytesRead,
          bytesRead,
        )
        if (count === 0) break
        bytesRead += count
      }
      const shortRead = bytesRead < buffer.length
      const included = buffer.subarray(0, Math.min(bytesRead, limit))
      const content = included.toString("utf8")
      const replacementCount = [...content].filter((character) => character === "\uFFFD").length
      if (included.includes(0) || replacementCount > Math.max(2, content.length / 100)) {
        return {
          source: "file",
          path: resolved,
          status: "blocked",
          reason: "binary or non-text content",
          size: info.size,
        }
      }
      if (SENSITIVE_CONTENT.test(content)) {
        return {
          source: "file",
          path: resolved,
          status: "blocked",
          reason: "possible literal credential or private key",
          size: info.size,
          includedSha256: sha256(included),
        }
      }
      return {
        source: "file",
        path: resolved,
        status: info.size > limit || shortRead ? "truncated" : "included",
        size: info.size,
        includedBytes: included.length,
        includedSha256: sha256(included),
        content,
      }
    } finally {
      await handle.close()
    }
  } catch (error) {
    return {
      source: "file",
      path: isAbsolute(source) ? source : resolved,
      status: "unavailable",
      reason: error instanceof Error ? error.message : String(error),
    }
  }
}

function isMissingFile(result: FileEvidence): boolean {
  return (
    result.status === "unavailable" &&
    /\bENOENT\b|no such file or directory/i.test(result.reason ?? "")
  )
}

export async function includeEvidenceFile(
  source: string,
  directory: string,
  rootDirectory: string,
  worktree: string,
  maxChars: number,
): Promise<FileEvidence> {
  const first = await includeFileOnce(source, directory, rootDirectory, worktree, maxChars)
  if (!isMissingFile(first)) return first
  await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, 100))
  return includeFileOnce(source, directory, rootDirectory, worktree, maxChars)
}

function deterministicDenial(stdin: FileEvidence | undefined): string | undefined {
  if (!stdin) return
  if (isMissingFile(stdin)) {
    return `The file sent over stdin does not exist after a second check: ${stdin.path}. Create it and retry the command.`
  }
  return
}

function commandSignals(remoteCommand: string, hasStdin: boolean): Record<string, boolean> {
  return {
    stagingHint: /\bstag(?:e|ing)?\b/i.test(remoteCommand),
    productionHint: /\bprod(?:uction)?\b/i.test(remoteCommand),
    executesStdin: hasStdin && /\b(?:python(?:3)?|bash|sh|node|ruby|perl)\s+-$/.test(remoteCommand),
    secretReadHint:
      /\b(?:env|printenv)\b|(?:^|[\s/])\.env\b|\/proc\/\d+\/environ\b|(?:cat|sed|grep)\s+[^\n;]*(?:credential|secret|token|private[_-]?key)/i.test(
        remoteCommand,
      ),
    mutationHint:
      /\b(?:rm|mv|cp|install|deploy|restart|stop|start|kill|reboot|shutdown|chmod|chown|truncate|tee|docker\s+(?:rm|restart|stop|kill|compose\s+(?:up|down))|kubectl\s+(?:apply|delete|patch|rollout)|systemctl\s+(?:restart|stop|start|enable|disable))\b/i.test(
        remoteCommand,
      ),
  }
}

export function analyzeScriptContent(content: string): Record<string, unknown> {
  const outboundUrls = [...content.matchAll(/https?:\/\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]+/g)]
    .map((match) => match[0])
    .slice(0, 8)
  return {
    credentialPathReadHint:
      /(?:read_text|read_bytes|open)\s*\([^)]*(?:\.ssh\/id_|\.aws\/credentials|\.env\b|credential|private[_-]?key)/i.test(
        content,
      ) ||
      /Path\s*\([^)]*(?:\.ssh\/id_|\.aws\/credentials|\.env\b|credential|private[_-]?key)[^)]*\)\s*\.\s*(?:read_text|read_bytes|open)/i.test(
        content,
      ),
    environmentEnumerationHint:
      /\bos\.environ\b|\bprocess\.env\b|\bprintenv\b|(?:^|[^\w])env(?:[^\w]|$)/m.test(content),
    networkUploadHint:
      /\brequests?\.(?:post|put|patch)\s*\(|\burlopen\s*\([^)]*(?:data\s*=|Request)|\bmethod\s*=\s*["'](?:POST|PUT|PATCH)["']|\bcurl\b[^\n]*(?:--data|-d\b|-T\b|--upload-file)/i.test(
        content,
      ),
    dynamicExecutionHint:
      /\b(?:exec|eval|compile)\s*\(|\bsubprocess\.(?:run|Popen|call)\s*\(|\bos\.system\s*\(|\bchild_process\.(?:exec|spawn)\s*\(/i.test(
        content,
      ),
    fileMutationHint:
      /\.(?:write_text|write_bytes|unlink|rename|replace)\s*\(|\bopen\s*\([^)]*,\s*["'][wax+]|\bshutil\.(?:rmtree|move|copy|copy2)\s*\(|\bos\.(?:remove|unlink|rename|replace)\s*\(/i.test(
        content,
      ),
    databaseMutationHint:
      /\b(?:alter|drop|truncate|delete\s+from|update|insert\s+into|create\s+(?:table|index)|grant|revoke)\b/i.test(
        content,
      ),
    outboundUrls,
  }
}

function stdinSignals(stdin: FileEvidence | undefined): Record<string, unknown> | undefined {
  if (!stdin?.content) return
  return analyzeScriptContent(stdin.content)
}

export async function enrichSshEvidence(
  request: PermissionRequest,
  directory: string,
  worktree: string,
  maxChars: number,
): Promise<SshEnrichmentResult> {
  if (request.permission !== "bash") return { text: "", audit: [] }
  const command = sourceCommand(request)

  // Track the working directory across `cd` chains, subshell groups, and
  // pipelines (same representation the local-script and git enrichments use)
  // so a stdin source resolves where the producing command runs, not against
  // the ssh segment's directory.
  const segments = shellCommandSegmentsWithDirectory(command, directory)
  const records: Array<Record<string, unknown>> = []
  const audit: SshAuditSummary[] = []
  const preflightDenials: string[] = []

  for (let segmentIndex = 0; segmentIndex < segments.length; segmentIndex += 1) {
    const segment = segments[segmentIndex]!
    const sshIndex = findSshIndex(segment.tokens)
    if (sshIndex < 0) continue
    const parsed = parseSsh(segment.tokens, sshIndex)
    if (!parsed) continue

    // The pipeline producer runs where IT runs, not where ssh runs: a group
    // like `(cd sub && cat p.py) | ssh …` reads the stdin file from sub even
    // though ssh itself executes in the outer directory. Walk back over
    // paren markers to the producing command.
    let producerIndex = segmentIndex - 1
    while (producerIndex >= 0 && segments[producerIndex]!.tokens.length === 0) producerIndex -= 1
    const producer = producerIndex >= 0 ? segments[producerIndex]! : undefined
    const stdinPath = segment.preceding === "|" && producer ? catSource(producer.tokens) : undefined
    const stdin =
      stdinPath === undefined
        ? undefined
        : producer !== undefined && producer.directory === undefined && !isAbsolute(stdinPath)
          ? {
              source: "file" as const,
              path: stdinPath,
              status: "unavailable" as const,
              reason:
                producer.directoryReason ??
                "working directory of the pipeline producer is unresolved",
            }
          : await includeEvidenceFile(
              stdinPath,
              producer?.directory ?? segment.directory ?? directory,
              directory,
              worktree,
              maxChars,
            )
    const remoteCommandSha256 = parsed.remoteCommand ? sha256(parsed.remoteCommand) : undefined
    const analyzedStdin = stdinSignals(stdin)
    const denial = deterministicDenial(stdin)
    if (denial) preflightDenials.push(denial)
    const record = {
      kind: "ssh",
      destination: parsed.destination,
      host: parsed.host,
      ...(parsed.user === undefined ? {} : { user: parsed.user }),
      ...(parsed.port === undefined ? {} : { port: parsed.port }),
      ...(parsed.identityFile === undefined ? {} : { identityFile: parsed.identityFile }),
      ...(parsed.strictHostKeyChecking === undefined
        ? {}
        : { strictHostKeyChecking: parsed.strictHostKeyChecking }),
      remoteCommand: parsed.remoteCommand || "<interactive or unspecified>",
      ...(remoteCommandSha256 === undefined ? {} : { remoteCommandSha256 }),
      signals: commandSignals(parsed.remoteCommand, stdin !== undefined),
      ...(analyzedStdin === undefined ? {} : { stdinSignals: analyzedStdin }),
      ...(stdin === undefined
        ? segment.preceding === "|"
          ? {
              stdin: {
                status: "unresolved",
                reason: "pipeline producer is not one regular cat file",
              },
            }
          : {}
        : { stdin }),
    }
    records.push(record)
    audit.push({
      destination: parsed.destination,
      ...(parsed.port === undefined ? {} : { port: parsed.port }),
      ...(remoteCommandSha256 === undefined ? {} : { remoteCommandSha256 }),
      ...(stdin === undefined ? {} : { stdinSource: stdin.path, stdinStatus: stdin.status }),
      ...(stdin?.reason === undefined ? {} : { stdinReason: stdin.reason }),
    })
  }

  if (records.length === 0) return { text: "", audit: [] }
  const serialized = JSON.stringify(records, null, 2)
  const bounded =
    serialized.length <= maxChars
      ? serialized
      : `${serialized.slice(0, maxChars)}\n<ssh_enrichment_truncated characters="${serialized.length - maxChars}" />`
  return {
    text: `SSH_ANALYSIS\n${bounded}`,
    audit,
    ...(preflightDenials.length === 0 ? {} : { preflightDenial: preflightDenials.join(" ") }),
  }
}
