import { execFile } from 'node:child_process'
import { promises as fs } from 'node:fs'
import { devNull } from 'node:os'
import { isAbsolute, join, relative, sep } from 'node:path'

/** Run a read-only command (git). shell:false — no shell injection. For git, we
 *  additionally neutralize the target repo's OWN config (fsmonitor/pager/hooks
 *  are code-exec-on-"read" surfaces) and point global/system config at /dev/null,
 *  so "never runs the repository's own code" actually holds. Never rejects. */
export function run(cmd: string, args: string[], cwd: string, timeoutMs = 15_000): Promise<{ code: number; stdout: string; stderr: string }> {
  let finalArgs = args
  let env = process.env
  if (cmd === 'git') {
    finalArgs = ['-c', 'core.fsmonitor=false', '-c', 'core.pager=cat', '-c', 'core.hooksPath=' + devNull, '--no-optional-locks', ...args]
    env = { ...process.env, GIT_CONFIG_GLOBAL: devNull, GIT_CONFIG_SYSTEM: devNull, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' }
  }
  return new Promise((resolve) => {
    execFile(cmd, finalArgs, { cwd, timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024, windowsHide: true, shell: false, env }, (err, stdout, stderr) => {
      const code = err && typeof (err as { code?: unknown }).code === 'number' ? (err as { code: number }).code : err ? 1 : 0
      resolve({ code, stdout: stdout ?? '', stderr: stderr ?? '' })
    })
  })
}

// Directories never worth walking — noise, and (node_modules/.git) potentially huge.
const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', 'build', 'out', '.next', 'coverage', 'vendor', '.venv', 'venv', '__pycache__', 'target', '.cache', 'tmp', '.turbo'])

export interface WalkResult {
  files: string[] // repo-relative
  dirs: string[] // top-level dir names present
  truncated: boolean
}

/**
 * Bounded, breadth-first repo walk. Skips heavy/noise dirs and symlinks (never
 * follows a link out of the tree — a hostile repo can't make us traverse the host
 * filesystem). Bounded by files AND directories AND depth, so a tree that is
 * (almost) all nested/empty directories can't stall the scout or grow the queue
 * unbounded.
 */
export async function walkRepo(root: string, maxFiles = 4000, maxDirs = 20_000, maxDepth = 24): Promise<WalkResult> {
  const files: string[] = []
  const topDirs = new Set<string>()
  let truncated = false
  let dirsVisited = 0
  const queue: Array<{ dir: string; depth: number }> = [{ dir: root, depth: 0 }]

  while (queue.length && files.length < maxFiles) {
    if (dirsVisited >= maxDirs) { truncated = true; break }
    const { dir, depth } = queue.shift()!
    dirsVisited++
    let entries
    try {
      entries = await fs.readdir(dir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const e of entries) {
      if (files.length >= maxFiles) {
        truncated = true
        break
      }
      const abs = join(dir, e.name)
      // Never traverse symlinks: a link could point outside the repo (host FS).
      if (e.isSymbolicLink()) continue
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || (e.name.startsWith('.') && e.name !== '.github' && e.name !== '.repotector')) continue
        if (depth >= maxDepth) { truncated = true; continue }
        if (dir === root) topDirs.add(e.name)
        queue.push({ dir: abs, depth: depth + 1 })
      } else if (e.isFile()) {
        files.push(relative(root, abs).split(sep).join('/'))
      }
    }
  }
  return { files, dirs: [...topDirs], truncated }
}

/** Read at most `maxBytes` from a file WITHOUT buffering the whole thing first
 *  (a 2 GB manifest must not OOM the host). Single positional read into a fixed
 *  buffer. Returns null on any error or non-regular file. */
async function boundedRead(path: string, maxBytes: number): Promise<string | null> {
  let fh: Awaited<ReturnType<typeof fs.open>> | null = null
  try {
    fh = await fs.open(path, 'r')
    const st = await fh.stat()
    if (!st.isFile()) return null // refuse fifos/devices/dirs
    const len = Math.min(maxBytes, st.size)
    const buf = Buffer.allocUnsafe(len)
    const { bytesRead } = await fh.read(buf, 0, len, 0)
    return buf.subarray(0, bytesRead).toString('utf8')
  } catch {
    return null
  } finally {
    await fh?.close().catch(() => {})
  }
}

/** Read a file produced by the (symlink-safe) walk. Bounded; the walk already
 *  guarantees containment, so no extra realpath check is needed here. */
export async function readTextCapped(path: string, maxBytes = 256 * 1024): Promise<string | null> {
  return boundedRead(path, maxBytes)
}

/** Read a file by a path we compute directly (manifest, lockfile, .repotector
 *  ledger, README) — these BYPASS the walk, so they must be contained explicitly:
 *  resolve symlinks and refuse anything that escapes the repo root. This is what
 *  stops a hostile `.repotector/register.jsonl -> ~/.ssh/id_rsa` symlink from
 *  exfiltrating a host file into the brief. */
export async function readTextContained(root: string, target: string, maxBytes = 256 * 1024): Promise<string | null> {
  const real = await realpathUnder(root, target)
  return real ? boundedRead(real, maxBytes) : null
}

/** Contained existence check: true only if the path resolves to something still
 *  inside the repo root (a symlink pointing outside reads as "not present"). */
export async function existsContained(root: string, target: string): Promise<boolean> {
  return (await realpathUnder(root, target)) !== null
}

/** Resolve `target` (abs or root-relative) through symlinks and return its real
 *  path only if it stays inside the repo root; else null. */
async function realpathUnder(root: string, target: string): Promise<string | null> {
  try {
    const abs = isAbsolute(target) ? target : join(root, target)
    const realRoot = await fs.realpath(root)
    let realTarget: string
    try {
      realTarget = await fs.realpath(abs)
    } catch {
      return null // does not exist / broken link
    }
    if (realTarget === realRoot) return realTarget
    const rel = relative(realRoot, realTarget)
    if (rel.startsWith('..') || isAbsolute(rel)) return null // escaped the repo root
    return realTarget
  } catch {
    return null
  }
}

export async function exists(path: string): Promise<boolean> {
  try {
    await fs.access(path)
    return true
  } catch {
    return false
  }
}
