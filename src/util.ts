import { execFile } from 'node:child_process'
import { promises as fs } from 'node:fs'
import { join, relative, sep } from 'node:path'

/** Run a read-only command (git). shell:false — no shell injection. Resolves with
 *  {code,stdout,stderr}; never rejects on a non-zero exit. */
export function run(cmd: string, args: string[], cwd: string, timeoutMs = 15_000): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(cmd, args, { cwd, timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024, windowsHide: true, shell: false }, (err, stdout, stderr) => {
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
 * filesystem). Stops at maxFiles so a giant monorepo can't stall the scout.
 */
export async function walkRepo(root: string, maxFiles = 4000): Promise<WalkResult> {
  const files: string[] = []
  const topDirs = new Set<string>()
  let truncated = false
  const queue: string[] = [root]

  while (queue.length && files.length < maxFiles) {
    const dir = queue.shift()!
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
        if (SKIP_DIRS.has(e.name) || e.name.startsWith('.') && e.name !== '.github' && e.name !== '.repotector') continue
        if (dir === root) topDirs.add(e.name)
        queue.push(abs)
      } else if (e.isFile()) {
        files.push(relative(root, abs).split(sep).join('/'))
      }
    }
  }
  return { files, dirs: [...topDirs], truncated }
}

/** Read a small text file safely (bounded); returns null on any error. */
export async function readTextCapped(path: string, maxBytes = 256 * 1024): Promise<string | null> {
  try {
    const buf = await fs.readFile(path)
    return buf.subarray(0, maxBytes).toString('utf8')
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
