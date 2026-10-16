/*
 * Minimal shell-aware tokenizer used by the deterministic emergency brake.
 *
 * This is NOT a full shell interpreter. It performs just enough static
 * analysis to evaluate the *real* executable of a command:
 *   - grouping of single/double quotes (so separators inside quotes do not
 *     split a token, and `printf "a; sudo rm -rf /"` stays one argument),
 *   - splitting on logical command separators (`;`, `|`, `&`, newlines),
 *   - stripping `#` comments when they begin a token,
 *   - a recursive "effective command" resolver that peels privilege wrappers
 *     (`sudo`, `doas`, `env`, `command`, `nice`, `nohup`, `time`, `stdbuf`,
 *     `ionice`, `pkexec`, `fakeroot`, `setsid`, `setpriv`, `unshare`, `run0`,
 *     `watch`, `xargs`) and destructures command-string forms (`sh -c`,
 *     `su -c`, `env -S`, `ssh host cmd`, `busybox applet`, `chroot root cmd`,
 *     `timeout duration cmd`).
 *
 * It deliberately does NOT expand variables, globs, command substitutions,
 * heredocs, or arithmetic. Those remain the model reviewer's job; the brake
 * is only a last line of defense for *unmistakable* literal destruction.
 * Command-string recursion depth and the total number of resolved effective
 * commands are hard-capped, so adversarial nesting can neither exhaust the
 * stack nor expand the result without bound.
 */

export interface ShellToken {
  /** Original text including any surrounding quotes. */
  raw: string
  /** Unquoted/normalized value used for comparisons. */
  value: string
  /** Value split into spans by quoting: every character of `value` appears
   *  in exactly one span, marked `quoted` when it came from inside quotes
   *  or from a backslash escape. An operator character (`>`, `*`, …) only
   *  acts as an operator while it sits in an UNQUOTED span: a glued, partly
   *  quoted `>"/dev/sda"` still redirects, while `'>/dev/sda'` is data. */
  spans?: Array<{ text: string; quoted: boolean }>
}

export interface ShellSegment {
  tokens: ShellToken[]
  /** Separator that terminated this segment (`;`, `|`, `||`, `&`, `&&`, `(`,
   *  `)`). Newlines and carriage returns are reported as `;`. Absent for the
   *  final segment when the command does not end with a separator. A segment
   *  with no tokens and `endedBy` `(` or `)` is a paren marker: it exists so
   *  grouping events are never lost, and carries no command of its own. */
  endedBy?: string
  /** The last separator seen before this segment's first token, counting
   *  separators whose (empty) segment was dropped: in `( a ) | b`, segment
   *  `b` ended up after a dropped empty segment, so its separator lineage is
   *  `)` and then `|`, and `precededBy` reports `|`. Absent for the first
   *  segment. */
  precededBy?: string
}

export interface ShellRedirection {
  operator: string
  target: string
  quoted: boolean
}

/** Segments flattened to plain token values plus the separators around each
 *  segment. This is the shared surface evidence consumers (SSH, Git, local
 *  scripts) build on, so the brake's lexer stays the one tokenizer. */
export interface CommandSegment {
  tokens: string[]
  preceding?: string
  endedBy?: string
}

export function commandSegments(command: string): CommandSegment[] {
  return lexSegments(command).map((segment) => {
    const normalized = normalizeShellRedirections(segment.tokens)
    return {
      tokens: normalized.tokens.map((token) => token.value),
      ...(segment.precededBy === undefined ? {} : { preceding: segment.precededBy }),
      ...(segment.endedBy === undefined ? {} : { endedBy: segment.endedBy }),
    }
  })
}

const SEPARATORS = new Set([";", "|", "&", "\n", "\r", "(", ")"])
const WHITESPACE = new Set([" ", "\t"])

const TRANSPARENT_WRAPPERS = new Set([
  "sudo",
  "doas",
  "pkexec",
  "env",
  "command",
  "nice",
  "nohup",
  "time",
  "stdbuf",
  "ionice",
  "fakeroot",
  "setsid",
  "setpriv",
  "unshare",
  "run0",
  "systemd-run",
  "strace",
  "ltrace",
  "watch",
  "xargs",
  "timeout",
  "exec",
])

/**
 * Wrapper short options that consume the next token as their value. Only flags
 * documented to take an argument are listed; pure flags (sudo -S/-A, unshare
 * --mount/--pid/…, run0 --mkdir/--no-ask-password) are intentionally absent so
 * the real executable that follows them is not swallowed by mistake.
 */
const VALUE_OPTIONS: Record<string, Set<string>> = {
  sudo: new Set([
    "-u",
    "--user",
    "-g",
    "--group",
    "-C",
    "-p",
    "--prompt",
    "-R",
    "-T",
    "-U",
    "-D",
    "--chdir",
    "-r",
    "-t",
  ]),
  doas: new Set(["-u", "--user", "-a"]),
  pkexec: new Set(["--user", "--session"]),
  env: new Set(["-u", "--unset", "-S", "--split-string", "-C", "--chdir"]),
  nice: new Set(["-n", "--adjustment"]),
  time: new Set(["-o", "--output", "-f"]),
  ionice: new Set(["-c", "-n"]),
  setpriv: new Set([
    "--ruid",
    "--euid",
    "--rgid",
    "--egid",
    "--reuid",
    "--regid",
    "--inh-caps",
    "--bounding-set",
    "--ambient-caps",
    "--groups",
    "--securebits",
    "--pdeathsig",
    "--selinux-label",
    "--apparmor-profile",
  ]),
  command: new Set(),
  nohup: new Set(),
  // stdbuf's -i/-o/-e take the buffer TYPE either attached (`-oL`) or as the
  // next token; both forms skip exactly one value.
  stdbuf: new Set(["-i", "-o", "-e", "--input", "--output", "--error"]),
  fakeroot: new Set(),
  setsid: new Set(),
  unshare: new Set([
    "--propagation",
    "--setgroups",
    "-R",
    "--root",
    "-w",
    "--wd",
    "-S",
    "--setuid",
    "-G",
    "--setgid",
    "--monotonic",
    "--boottime",
  ]),
  run0: new Set(["--unit", "--service", "--slice", "--setenv", "--chdir"]),
  // systemd-run mostly uses = forms (self-contained tokens); the flags listed
  // here also accept a separate value token that must not be mistaken for the
  // wrapped command.
  "systemd-run": new Set([
    "-p",
    "-E",
    "-H",
    "--host",
    "-M",
    "--property",
    "-u",
    "--unit",
    "--description",
    "--slice",
    "--uid",
    "--gid",
    "--nice",
    "--expand-environment",
    "--service-type",
    "--working-directory",
    "--setenv",
    "--machine",
    "--job-mode",
    "--on-active",
    "--on-boot",
    "--on-startup",
    "--on-calendar",
    "--on-unit-active",
    "--on-unit-inactive",
    "--timer-property",
    "--path-property",
    "--socket-property",
  ]),
  // strace/ltrace: -o/-e/-s take a separate value; their long forms are
  // = only. Tracing without a command (`strace -p PID`) has nothing to peel
  // after the PID is consumed.
  strace: new Set(["-o", "-e", "-s", "-a", "-b", "-p", "-u"]),
  ltrace: new Set(["-o", "-e", "-s", "-a", "-l", "-u"]),
  // watch's interval and equexit flags consume separate values; its pure flags
  // (-d, -g, -t, -b, -c, -e, …) stay absent like the other wrappers above.
  watch: new Set(["-n", "--interval", "-q", "--equexit"]),
  // xargs value-taking options with a separate argument: without these the
  // generic peel would mistake the option's argument for the command. Pure
  // flags (-0, -r, -t, …) stay absent, as do options with optional arguments
  // (-e, -l, --replace), where skipping a following token could swallow the
  // real executable instead.
  xargs: new Set([
    "-I",
    "-a",
    "-d",
    "-E",
    "-n",
    "-P",
    "-s",
    "-L",
    "--arg-file",
    "--delimiter",
    "--max-args",
    "--max-chars",
    "--max-procs",
    "--max-lines",
    "--process-slot-var",
  ]),
  // timeout value options; the DURATION operand itself is skipped by dedicated
  // handling in walk(), not by the generic loop.
  timeout: new Set(["-k", "-s", "--kill-after", "--signal"]),
  exec: new Set(["-a"]),
}

const SHELL_BINARIES = new Set(["sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "fish"])
const SU_BINARIES = new Set(["su", "runuser", "super"])

/** Ceiling on command-string re-entry (`sh -c`, `env -S`, ssh, busybox,
 *  chroot). Deeper nesting than this is not a legitimate review shape; the
 *  lexer stops descending and the unanalyzed remainder stays the model
 *  reviewer's job, keeping unbounded input from exhausting the stack. */
const MAX_WALK_DEPTH = 32

/** Ceiling on collected effective commands. Command strings can expand
 *  combinatorially (a level duplicating its script doubles the output), so
 *  past this bound collection stops instead of exhausting time or memory on
 *  adversarial input. */
const MAX_EFFECTIVE_COMMANDS = 4096

/** Hard cap on the raw text a single lexing pass accepts, and on the tokens
 *  it may materialize, both checked BEFORE building large structures. */
export const MAX_ANALYSIS_INPUT_CHARS = 131_072
const MAX_LEX_TOKENS = 16_384
const MAX_REANALYSIS_CHARS = 262_144

/** Per-request analysis budget: one instance covers a whole permission
 *  request (every segment, every nested command string), not a single
 *  segment. Without shared counters, an input made of thousands of small
 *  segments stayed under every per-call ceiling while the TOTAL work grew
 *  without bound. `remainingReanalysisChars` bounds the text re-lexed while
 *  destructuring command strings (`sh -c '…'`, `env -S …`). */
export interface AnalysisBudget {
  remainingCommands: number
  remainingReanalysisChars: number
}

export function newAnalysisBudget(): AnalysisBudget {
  return {
    remainingCommands: MAX_EFFECTIVE_COMMANDS,
    remainingReanalysisChars: MAX_REANALYSIS_CHARS,
  }
}
const SSH_VALUE_OPTIONS = new Set([
  "-i",
  "-l",
  "-p",
  "-o",
  "-F",
  "-J",
  "-b",
  "-c",
  "-e",
  "-m",
  "-w",
  "-W",
  "-D",
  "-L",
  "-R",
  "-I",
  "-Q",
  "-O",
  "-E",
])

/** First value-taking option in an OpenSSH short-option cluster. The value is
 * either attached to the cluster or supplied by the following token. */
export function sshValueOption(token: string): { option: string; attached?: string } | undefined {
  if (!token.startsWith("-") || token.startsWith("--") || token.length <= 1) return
  for (let position = 1; position < token.length; position += 1) {
    const option = `-${token[position]!}`
    if (!SSH_VALUE_OPTIONS.has(option)) continue
    const attached = token.slice(position + 1)
    return attached ? { option, attached } : { option }
  }
  return
}
const SHELL_KEYWORDS = new Set(["{", "}", "(", ")", "then", "else", "do", "elif", "!"])

function basename(exe: string): string {
  const slash = exe.lastIndexOf("/")
  return slash >= 0 ? exe.slice(slash + 1) : exe
}

/** Whether the character at `index` of `token.value` lies in a quoted or
 *  escaped span, where it cannot act as a shell operator. Tokens without
 *  span information fall back to whole-token conservatism. */
export function tokenCharIsQuoted(token: ShellToken, index: number): boolean {
  const spans = token.spans
  if (spans === undefined) return token.raw !== token.value
  let offset = 0
  for (const span of spans) {
    if (index < offset + span.text.length) return span.quoted
    offset += span.text.length
  }
  return false
}

/**
 * Tokenize `command` into logical segments (one per sub-command separated by
 * `;`, `|`, `&`, or newline) with quote-aware, comment-aware grouping.
 * `state.tokensRemaining` (when given) is decremented per token and stops
 * the scan at zero: callers that must not miss tail content use
 * `lexSegmentsBounded` and treat the stop as a truncation fact.
 */
export function lexSegments(command: string, state?: { tokensRemaining: number }): ShellSegment[] {
  const segments: ShellSegment[] = []
  let tokens: ShellToken[] = []
  let value = ""
  let raw = ""
  let hasToken = false
  let spans: Array<{ text: string; quoted: boolean }> = []
  let inSingle = false
  let inDouble = false
  let lastSeparator: string | undefined
  let outOfTokens = false

  const appendValue = (text: string, quoted: boolean) => {
    if (text.length === 0) return
    const last = spans.at(-1)
    if (last !== undefined && last.quoted === quoted) last.text += text
    else spans.push({ text, quoted })
    value += text
  }

  const flushToken = () => {
    if (hasToken) {
      tokens.push({ raw, value, spans })
      value = ""
      raw = ""
      spans = []
      hasToken = false
      if (state !== undefined) {
        state.tokensRemaining -= 1
        if (state.tokensRemaining <= 0) outOfTokens = true
      }
    }
  }
  const flushSegment = (endedBy?: string) => {
    flushToken()
    // Paren separators survive as empty marker segments even without tokens:
    // the directory tracker needs every open/close event, and dropping the
    // empties left nested closes unbalanced (`( cd x; (a) ) b` restored the
    // wrong state after the group). Other empty flushes stay dropped.
    if (tokens.length > 0 || endedBy === "(" || endedBy === ")") {
      segments.push({
        tokens,
        ...(endedBy === undefined ? {} : { endedBy }),
        ...(lastSeparator === undefined ? {} : { precededBy: lastSeparator }),
      })
      tokens = []
    }
  }

  let i = 0
  while (i < command.length) {
    if (outOfTokens) break
    const c = command[i]!
    if (inSingle) {
      raw += c
      if (c === "'") inSingle = false
      else appendValue(c, true)
      i += 1
      continue
    }
    if (inDouble) {
      raw += c
      if (c === '"') {
        inDouble = false
      } else if (c === "\\" && i + 1 < command.length) {
        const next = command[i + 1]!
        raw += next
        // Inside double quotes bash only unescapes $ ` " \ and the newline
        // (a line continuation). A backslash before any other character,
        // including `n`, stays a literal backslash in the value.
        if (next === "\n" || next === "\r") {
          i += 2
          continue
        }
        if ('$`"\\'.includes(next)) {
          appendValue(next, true)
          i += 2
          continue
        }
        appendValue("\\", true)
        i += 1
        continue
      } else {
        appendValue(c, true)
      }
      i += 1
      continue
    }
    if (c === "'") {
      inSingle = true
      raw += c
      hasToken = true
      i += 1
      continue
    }
    if (c === '"') {
      inDouble = true
      raw += c
      hasToken = true
      i += 1
      continue
    }
    // Redirection operators may contain characters that are command
    // separators elsewhere. Keep `&>`, `2>&1`, and `>|file` inside the token
    // so the redirection normalizer below can interpret them as one shell
    // construct instead of inventing extra commands.
    if (
      (c === "&" &&
        (command[i + 1] === ">" ||
          (value.endsWith(">") && !tokenCharIsQuoted({ raw, value, spans }, value.length - 1)))) ||
      (c === "|" &&
        value.endsWith(">") &&
        !tokenCharIsQuoted({ raw, value, spans }, value.length - 1))
    ) {
      appendValue(c, false)
      raw += c
      hasToken = true
      i += 1
      continue
    }
    if (SEPARATORS.has(c)) {
      // Capture the operator identity (including doubled `||`/`&&`) so
      // evidence consumers can reason about how segments relate.
      let endedBy = c === "\n" || c === "\r" ? ";" : c
      if ((c === "|" || c === "&") && command[i + 1] === c) {
        endedBy = `${c}${c}`
        i += 1
      }
      flushSegment(endedBy)
      lastSeparator = endedBy
      i += 1
      continue
    }
    if (WHITESPACE.has(c)) {
      flushToken()
      i += 1
      continue
    }
    if (c === "#" && !hasToken) {
      // Line comment: consume until newline (newline itself closes the segment).
      while (i < command.length && command[i] !== "\n") i += 1
      continue
    }
    if (c === "\\" && i + 1 < command.length) {
      const next = command[i + 1]!
      raw += "\\" + next
      // On Windows, an unquoted drive path keeps its separators. Bash would
      // eat them, but the host path and the evidence reader need them. Any
      // other unquoted escape, including backslash-newline, stays bash-compatible.
      // Linux never takes this branch.
      if (
        process.platform === "win32" &&
        next !== "\n" &&
        next !== "\r" &&
        /^[A-Za-z]:(?:\\[^\\]*)*$/.test(value)
      ) {
        appendValue("\\" + next, false)
        hasToken = true
        i += 2
        continue
      }
      // Backslash-newline is a line continuation outside quotes: both
      // characters vanish, so `r\<newline>m` lexes as the token `rm`.
      if (next !== "\n" && next !== "\r") {
        appendValue(next, true)
        hasToken = true
      }
      i += 2
      continue
    }
    appendValue(c, false)
    raw += c
    hasToken = true
    i += 1
  }
  if (!outOfTokens) flushSegment()
  return segments
}

/** Bounded lexing pass: refuses oversized input up front and stops at the
 *  token cap, reporting `truncated` so no caller mistakes a prefix for the
 *  whole command. */
export interface LexAnalysis {
  segments: ShellSegment[]
  truncated: boolean
}

export function lexSegmentsBounded(command: string): LexAnalysis {
  if (command.length > MAX_ANALYSIS_INPUT_CHARS) return { segments: [], truncated: true }
  const state = { tokensRemaining: MAX_LEX_TOKENS }
  const segments = lexSegments(command, state)
  return { segments, truncated: state.tokensRemaining <= 0 }
}

/**
 * Resolve a segment into its "effective commands" — the token lists starting
 * at each real executable, after peeling wrappers and destructuring
 * command-string forms. May yield multiple commands when a shell/su `-c` body
 * itself contains separators.
 */
export function effectiveCommands(segment: ShellSegment): ShellToken[][] {
  return analyzeEffectiveCommands(segment).commands
}

/** Result of bounded command-string resolution. `truncated` is true when the
 *  depth or expansion budget stopped the descent, meaning `commands` is a
 *  prefix of the real structure: parts of the command were never analyzed. */
export interface EffectiveCommandsAnalysis {
  commands: ShellToken[][]
  /** Redirections removed from each effective command, in matching order. */
  redirections: ShellRedirection[][]
  truncated: boolean
}

/** Resolve one segment into effective commands. Pass a shared `budget` to
 *  cover a whole request: without it, every segment gets a fresh ceiling and
 *  a wide input never reports truncation. */
export function analyzeEffectiveCommands(
  segment: ShellSegment,
  budget?: AnalysisBudget,
): EffectiveCommandsAnalysis {
  const out: ShellToken[][] = []
  const redirections: ShellRedirection[][] = []
  const state = { truncated: false }
  const b = budget ?? newAnalysisBudget()
  walk(segment.tokens, out, redirections, [], 0, state, b)
  return { commands: out, redirections, truncated: state.truncated }
}

function walk(
  tokens: ShellToken[],
  out: ShellToken[][],
  redirectionOut: ShellRedirection[][],
  inheritedRedirections: ShellRedirection[],
  depth: number,
  state: { truncated: boolean },
  budget: AnalysisBudget,
): void {
  // Depth and expansion budget: recursion here is driven by the (untrusted)
  // command text, so both bounds are hard stops, not tuning knobs. Hitting
  // either one marks the analysis truncated so downstream gates know the
  // collected commands do not cover the whole command.
  if (
    depth > MAX_WALK_DEPTH ||
    out.length >= MAX_EFFECTIVE_COMMANDS ||
    budget.remainingCommands <= 0
  ) {
    state.truncated = true
    return
  }
  const normalized = normalizeShellRedirections(tokens)
  tokens = normalized.tokens
  const commandRedirections = [...inheritedRedirections, ...normalized.redirections]
  let i = 0
  while (i < tokens.length && SHELL_KEYWORDS.has(tokens[i]!.value)) i += 1

  // Consume leading VAR=value assignments (env-style, only at the head).
  while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i]!.value)) i += 1

  while (i < tokens.length) {
    const tok = tokens[i]!
    if (tok.value === "--") {
      break
    }
    const base = basename(tok.value)
    if (base === "env") {
      // `env -S 'command string'` (or unquoted: `env -S cmd args…`) carries a
      // parsed command line, and any operands after the string are appended to
      // it. The option may be clustered (`env -iS 'rm -rf /'`), where getopt
      // takes the string from the rest of the cluster or, when S ends the
      // cluster, from the next token. Recurse into the concatenation so
      // `env -S rm -rf /` and `env -iS rm -rf /` are both caught.
      const s = findEnvSCommand(tokens, i + 1)
      if (s !== null && s.script.length > 0) {
        const tail = tokens
          .slice(s.tailIndex)
          .map((t) => t.value)
          .join(" ")
        const reanalyzed = tail ? `${s.script} ${tail}` : s.script
        budget.remainingReanalysisChars -= reanalyzed.length
        if (budget.remainingReanalysisChars < 0) {
          state.truncated = true
          return
        }
        for (const sub of lexSegments(reanalyzed))
          walk(sub.tokens, out, redirectionOut, commandRedirections, depth + 1, state, budget)
        return
      }
    }
    if (base === "timeout") {
      // timeout [OPTION]... DURATION COMMAND [ARG]...: unlike the generic
      // wrappers, a mandatory non-option DURATION operand sits between the
      // options and the command, so skip options, then exactly one duration
      // token, then recurse into the real command tail. With no command left
      // (plain `timeout 5` just errors) there is nothing to peel to.
      const valueOpts = VALUE_OPTIONS.timeout ?? new Set<string>()
      let j = i + 1
      while (j < tokens.length) {
        const opt = tokens[j]!.value
        if (opt === "--") {
          j += 1
          break
        }
        if (opt.startsWith("-") && opt.length > 1) {
          j = skipWrapperOption(tokens, j, valueOpts)
          continue
        }
        break
      }
      if (j < tokens.length) j += 1
      if (j < tokens.length)
        walk(tokens.slice(j), out, redirectionOut, commandRedirections, depth + 1, state, budget)
      return
    }
    if (TRANSPARENT_WRAPPERS.has(base)) {
      const valueOpts = VALUE_OPTIONS[base] ?? new Set<string>()
      i += 1
      while (i < tokens.length) {
        const opt = tokens[i]!.value
        if (opt === "--") {
          i += 1
          break
        }
        // Env-style VAR=value arguments that follow a wrapper (e.g. `env FOO=bar …`).
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(opt)) {
          i += 1
          continue
        }
        if (opt.startsWith("-") && opt.length > 1) {
          i = skipWrapperOption(tokens, i, valueOpts)
          continue
        }
        break
      }
      continue
    }
    if (base === "script") {
      // `script -c/--command '…'` runs a command string through a shell;
      // without it, script just starts an interactive session and there is
      // nothing to peel.
      const command = findCommandString(tokens, i + 1)
      if (command !== null) {
        budget.remainingReanalysisChars -= command.length
        if (budget.remainingReanalysisChars < 0) {
          state.truncated = true
          return
        }
        for (const sub of lexSegments(command))
          walk(sub.tokens, out, redirectionOut, commandRedirections, depth + 1, state, budget)
        return
      }
    }
    if (SHELL_BINARIES.has(base) || SU_BINARIES.has(base)) {
      const script = findCommandString(tokens, i + 1, SHELL_BINARIES.has(base) && base !== "fish")
      if (script !== null) {
        budget.remainingReanalysisChars -= script.length
        if (budget.remainingReanalysisChars < 0) {
          state.truncated = true
          return
        }
        for (const sub of lexSegments(script))
          walk(sub.tokens, out, redirectionOut, commandRedirections, depth + 1, state, budget)
        return
      }
    }
    if (base === "ssh") {
      const rest = consumeSshRemote(tokens, i + 1)
      if (rest.length > 0) {
        const remote = rest.map((t) => t.value).join(" ")
        budget.remainingReanalysisChars -= remote.length
        if (budget.remainingReanalysisChars < 0) {
          state.truncated = true
          return
        }
        for (const sub of lexSegments(remote))
          walk(sub.tokens, out, redirectionOut, commandRedirections, depth + 1, state, budget)
      }
      return
    }
    if (base === "busybox") {
      if (i + 1 < tokens.length)
        walk(
          tokens.slice(i + 1),
          out,
          redirectionOut,
          commandRedirections,
          depth + 1,
          state,
          budget,
        )
      return
    }
    if (base === "chroot") {
      // chroot [OPTION]... NEWROOT [COMMAND [ARG]...]: skip options, then the
      // NEWROOT token, then recurse into the real command tail.
      let j = i + 1
      while (j < tokens.length) {
        const opt = tokens[j]!.value
        if (opt === "--") {
          j += 1
          break
        }
        if (opt.startsWith("-") && opt.length > 1) {
          j += 1
          continue
        }
        break
      }
      if (j + 1 < tokens.length)
        walk(
          tokens.slice(j + 1),
          out,
          redirectionOut,
          commandRedirections,
          depth + 1,
          state,
          budget,
        )
      return
    }
    out.push(tokens.slice(i))
    redirectionOut.push(commandRedirections)
    budget.remainingCommands -= 1
    return
  }
}

/** Return a token slice while preserving quote provenance for each character. */
function sliceToken(token: ShellToken, start: number, end = token.value.length): ShellToken {
  const value = token.value.slice(start, end)
  const spans: Array<{ text: string; quoted: boolean }> = []
  let offset = 0
  for (const span of token.spans ?? [{ text: token.value, quoted: token.raw !== token.value }]) {
    const spanStart = offset
    const spanEnd = offset + span.text.length
    const from = Math.max(start, spanStart)
    const to = Math.min(end, spanEnd)
    if (from < to) {
      const text = span.text.slice(from - spanStart, to - spanStart)
      const previous = spans.at(-1)
      if (previous?.quoted === span.quoted) previous.text += text
      else spans.push({ text, quoted: span.quoted })
    }
    offset = spanEnd
  }
  return { raw: value, value, spans }
}

function redirectionOperatorAt(token: ShellToken, index: number): string | undefined {
  const value = token.value
  const live = (offset: number) =>
    offset < value.length && !tokenCharIsQuoted(token, offset) ? value[offset] : undefined
  const first = live(index)
  const tail = `${first ?? ""}${live(index + 1) ?? ""}${live(index + 2) ?? ""}`
  if (tail.startsWith("&>>")) return "&>>"
  if (tail.startsWith("<<<")) return "<<<"
  if (tail.startsWith("<<-")) return "<<-"
  for (const operator of ["&>", ">>", ">|", ">&", "<<", "<&", "<>"] as const) {
    if (tail.startsWith(operator)) return operator
  }
  if (first === ">" || first === "<") return first
  return undefined
}

function nextRedirection(
  token: ShellToken,
  start: number,
): { index: number; operator: string } | undefined {
  for (let index = start; index < token.value.length; index += 1) {
    const operator = redirectionOperatorAt(token, index)
    if (operator !== undefined) return { index, operator }
  }
  return undefined
}

/**
 * Split shell redirections away from command words. Shell accepts them before,
 * after, or glued to the executable and its arguments (`2>log cmd`,
 * `cmd>log`, `echo x>out`). Leaving those forms inside word tokens can hide the
 * real executable or make a redirection target look like an ordinary operand.
 */
export function normalizeShellRedirections(tokens: ShellToken[]): {
  tokens: ShellToken[]
  redirections: ShellRedirection[]
} {
  const words: ShellToken[] = []
  const redirections: ShellRedirection[] = []
  for (let tokenIndex = 0; tokenIndex < tokens.length; tokenIndex += 1) {
    const token = tokens[tokenIndex]!
    // The heredoc extractor inserts this inert marker after removing the body.
    // It is evidence metadata, not another input redirection.
    if (/^<HEREDOC:sha256:[a-f0-9]+>$/.test(token.value)) {
      words.push(token)
      continue
    }
    let cursor = 0
    let found = nextRedirection(token, cursor)
    if (found === undefined) {
      words.push(token)
      continue
    }
    while (found !== undefined) {
      let wordEnd = found.index
      let operator = found.operator
      const prefix = token.value.slice(cursor, found.index)
      // An all-digit prefix immediately before the operator is an IO number,
      // not a command word (`2>`, `10>>`).
      if (cursor === 0 && /^[0-9]+$/.test(prefix)) {
        operator = `${prefix}${operator}`
        wordEnd = cursor
      }
      if (wordEnd > cursor) words.push(sliceToken(token, cursor, wordEnd))

      const targetStart = found.index + found.operator.length
      const following = nextRedirection(token, targetStart)
      let targetToken: ShellToken | undefined
      if (targetStart < (following?.index ?? token.value.length)) {
        targetToken = sliceToken(token, targetStart, following?.index)
      } else if (following === undefined) {
        const candidate = tokens[tokenIndex + 1]
        if (candidate !== undefined && nextRedirection(candidate, 0)?.index !== 0) {
          tokenIndex += 1
          targetToken = candidate
        }
      }
      if (targetToken !== undefined) {
        redirections.push({
          operator,
          target: targetToken.value,
          quoted:
            targetToken.value.length > 0 &&
            Array.from({ length: targetToken.value.length }, (_, index) => index).some((index) =>
              tokenCharIsQuoted(targetToken!, index),
            ),
        })
      }
      cursor = following?.index ?? token.value.length
      found = following
    }
  }
  return { tokens: words, redirections }
}

/** Advance past one wrapper option token at `index`, returning the index of
 *  the next token. Short-option clusters follow getopt semantics: the value
 *  of a value-taking letter is either embedded as the rest of the cluster
 *  (`-uroot`, `-un` where `u` takes the value `n`) or, when the letter is
 *  last, is the next token (`-nu root`). Misreading a cluster would swallow
 *  the wrapped command or mistake the value for the executable, so `sudo -nu
 *  root rm …` must skip the cluster and `root` together. */
function skipWrapperOption(tokens: ShellToken[], index: number, valueOpts: Set<string>): number {
  const opt = tokens[index]!.value
  if (valueOpts.has(opt)) return index + 2
  if (opt.startsWith("--")) return index + 1
  const letters = opt.slice(1)
  for (let position = 0; position < letters.length; position += 1) {
    if (valueOpts.has(`-${letters[position]!}`)) {
      return position === letters.length - 1 ? index + 2 : index + 1
    }
  }
  return index + 1
}

/** Find a `-c`/`--command` command-string argument and return its (unquoted) value. */
function findCommandString(tokens: ShellToken[], start: number, shellFlags = false): string | null {
  let i = start
  let endOfFlags = false
  let shellCommandPending = false
  while (i < tokens.length) {
    const t = tokens[i]!.value
    if (!endOfFlags && t === "--") {
      if (shellFlags && shellCommandPending) {
        return i + 1 < tokens.length ? tokens[i + 1]!.value : null
      }
      endOfFlags = true
      i += 1
      continue
    }
    if (!endOfFlags && t === "-c") {
      if (shellFlags) {
        shellCommandPending = true
        i += 1
        continue
      }
      return i + 1 < tokens.length ? tokens[i + 1]!.value : null
    }
    // Long form: `--command` (next token) or `--command=VALUE`.
    if (!endOfFlags && t === "--command") {
      return i + 1 < tokens.length ? tokens[i + 1]!.value : null
    }
    if (!endOfFlags && t.startsWith("--command=")) {
      return t.slice("--command=".length)
    }
    if (shellFlags && shellCommandPending) {
      if (!endOfFlags && (t === "-o" || t === "-O")) {
        i += 2
        continue
      }
      if (!endOfFlags && (t.startsWith("-") || t.startsWith("+")) && t.length > 1) {
        i += 1
        continue
      }
      return t
    }
    // Short-flag cluster containing `c` (e.g. `bash -ic '...'`). getopt
    // semantics: when `c` ends the cluster its value is the next token;
    // when other letters follow (`script -c"rm -rf /"`, `-Sval`), the rest
    // of the cluster IS the value.
    if (!endOfFlags && t.startsWith("-") && !t.startsWith("--") && t.length > 1) {
      const cPosition = t.indexOf("c")
      if (cPosition === -1) {
        i += 1
        continue
      }
      // Shells treat every letter in -ce/-xec as a flag: the script is
      // the first non-option that follows. More shell options may still sit
      // between that cluster and the script (`sh -c -x -- '...'`). su and
      // script use getopt value semantics instead.
      if (shellFlags) {
        shellCommandPending = true
        i += 1
        continue
      }
      if (cPosition === t.length - 1) {
        return i + 1 < tokens.length ? tokens[i + 1]!.value : null
      }
      return t.slice(cPosition + 1)
    }
    i += 1
  }
  return null
}

/** Locate the command string carried by a (possibly clustered) `env -S`
 *  option, honoring the other value-taking env options on the way (`-u
 *  NAME`, `-C DIR`, long forms). The string is the next token when S ends
 *  the option token, or the rest of the token when another letter follows
 *  S. Scanning stops at the first operand: after it, the command has begun
 *  and there is no -S. */
function findEnvSCommand(
  tokens: ShellToken[],
  start: number,
): { script: string; tailIndex: number } | null {
  for (let i = start; i < tokens.length; i += 1) {
    const value = tokens[i]!.value
    if (value === "--") return null
    if (value.startsWith("--")) {
      if (value === "--split-string") {
        const script = tokens[i + 1]
        if (script === undefined) return null
        return { script: script.value, tailIndex: i + 2 }
      }
      if (value.startsWith("--split-string=")) {
        return { script: value.slice("--split-string=".length), tailIndex: i + 1 }
      }
      if (VALUE_OPTIONS.env!.has(value)) i += 1
      continue
    }
    if (!value.startsWith("-") || value.length <= 1) return null
    const letters = value.slice(1)
    for (let position = 0; position < letters.length; position += 1) {
      const letter = letters[position]!
      if (letter === "S") {
        if (position === letters.length - 1) {
          const script = tokens[i + 1]
          if (script === undefined) return null
          return { script: script.value, tailIndex: i + 2 }
        }
        return { script: letters.slice(position + 1), tailIndex: i + 1 }
      }
      // -u/-C/-P consume a value: the rest of the cluster, or the next
      // token when the letter ends the cluster.
      if (letter === "u" || letter === "C" || letter === "P") {
        if (position === letters.length - 1) i += 1
        break
      }
    }
  }
  return null
}

/** Consume ssh options + host and return the remaining remote-command tokens. */
function consumeSshRemote(tokens: ShellToken[], start: number): ShellToken[] {
  let i = start
  let hostSeen = false
  while (i < tokens.length) {
    const t = tokens[i]!.value
    if (t === "--") {
      i += 1
      break
    }
    if (t.startsWith("-") && t.length > 1) {
      const valued = sshValueOption(t)
      i += valued !== undefined && valued.attached === undefined ? 2 : 1
      continue
    }
    if (!hostSeen) {
      hostSeen = true
      i += 1
      continue
    }
    break
  }
  return tokens.slice(i)
}

export { basename as shellBasename }
