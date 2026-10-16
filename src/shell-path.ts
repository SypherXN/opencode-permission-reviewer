import * as posix from "node:path/posix"
import * as win32 from "node:path/win32"

/** A Windows drive path (`C:\` or `C:/`) or a UNC path. */
export function isWindowsAbsolute(value: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(value) || value.startsWith("\\\\")
}

/** Absolute in the shell sense: a POSIX root path or a Windows drive/UNC path.
 *  A leading slash stays POSIX even on Windows, where `path.win32` would
 *  otherwise attach the current drive and turn `/workspace` into `C:\workspace`. */
export function isCommandAbsolute(value: string): boolean {
  return value.startsWith("/") || isWindowsAbsolute(value)
}

function normalizeCommandPath(value: string): string {
  if (value.startsWith("/")) return posix.normalize(value)
  if (isWindowsAbsolute(value)) return win32.normalize(value)
  return process.platform === "win32" ? win32.normalize(value) : posix.normalize(value)
}

/** Resolve a path that appears in a shell command.
 *  POSIX absolute paths stay POSIX on every host. Drive paths use Windows
 *  rules. A relative target follows the form of its base directory. */
export function resolveCommandPath(directory: string, target?: string): string {
  if (target === undefined) {
    if (directory.startsWith("/") || isWindowsAbsolute(directory))
      return normalizeCommandPath(directory)
    return process.platform === "win32" ? win32.resolve(directory) : posix.resolve(directory)
  }
  if (target.startsWith("/")) return posix.normalize(target)
  if (isWindowsAbsolute(target)) return win32.normalize(target)
  if (directory.startsWith("/")) return posix.resolve(directory, target)
  if (isWindowsAbsolute(directory) || process.platform === "win32")
    return win32.resolve(directory, target)
  return posix.resolve(directory, target)
}

/** Whether `path` is `root` or a descendant, using the separator of those paths. */
export function commandWithin(path: string, root: string): boolean {
  const left = normalizeCommandPath(path)
  const right = normalizeCommandPath(root)
  if (left === right) return true
  const leftWindows = left.includes("\\")
  const rightWindows = right.includes("\\")
  if (leftWindows !== rightWindows) return false
  const sep = leftWindows ? "\\" : "/"
  const prefix = right.endsWith(sep) ? right : `${right}${sep}`
  return left.startsWith(prefix)
}
