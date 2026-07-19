import { stripInjection } from '@dir-ai/voyager'
import { readTextContained, existsContained } from './util.js'
import type { ManifestFacts, FramedText } from './types.js'

/** Build a FramedText: injection-stripped, with a count of what was removed. */
export function frame(raw: string | null | undefined, source: string): FramedText | null {
  if (!raw) return null
  const trimmed = raw.trim()
  if (!trimmed) return null
  const framed = stripInjection(trimmed)
  // Count actual neutralization markers inserted (not a binary changed/not), so a
  // benign NFKC normalization doesn't falsely report a stripped payload.
  const markers = (framed.match(/\[(?:stripped|redacted)[^\]]*\]/gi) ?? []).length
  const stripped = markers > 0 ? markers : framed !== trimmed && /[<>]|ignore\b|system\s*:/i.test(trimmed) ? 1 : 0
  return { framed: framed.slice(0, 600), stripped, source }
}

/** Neutralize a short owner-controlled string that enters the brief INLINE
 *  (name/version/dep-name/path/script). Injection-stripped so raw owner bytes
 *  never reach the agent as instructions. */
export function cleanInline(raw: string, max = 214): string {
  return stripInjection(String(raw)).replace(/\s+/g, ' ').trim().slice(0, max)
}

/** Detect the ecosystem and read its manifest into normalized facts. Owner text
 *  is FRAMED/cleaned — never raw. Every read is containment-checked, so a
 *  symlinked manifest can't leak a host file into the brief. */
export async function scanManifest(root: string): Promise<ManifestFacts | null> {
  // npm
  const pj = await readTextContained(root, 'package.json')
  if (pj) {
    try {
      const j = JSON.parse(pj) as {
        name?: string; version?: string; description?: string; main?: string
        bin?: string | Record<string, string>
        scripts?: Record<string, string>
        dependencies?: Record<string, string>; peerDependencies?: Record<string, string>
      }
      // Which package manager? Read the SPECIFIC lockfile so the agent isn't told
      // to `npm install` in a pnpm/yarn repo (which would corrupt the lockfile).
      const hasPnpm = await existsContained(root, 'pnpm-lock.yaml')
      const hasYarn = await existsContained(root, 'yarn.lock')
      const hasNpm = await existsContained(root, 'package-lock.json')
      const packageManager = hasPnpm ? 'pnpm' : hasYarn ? 'yarn' : hasNpm ? 'npm' : null
      // Authoritative entrypoints from main + bin (cleaned — owner-controlled paths).
      const entryHints: string[] = []
      if (typeof j.main === 'string') entryHints.push(cleanInline(j.main))
      if (typeof j.bin === 'string') entryHints.push(cleanInline(j.bin))
      else if (j.bin && typeof j.bin === 'object') for (const v of Object.values(j.bin)) if (typeof v === 'string') entryHints.push(cleanInline(v))
      return {
        ecosystem: 'npm',
        name: j.name ? cleanInline(j.name) : null,
        version: j.version ? cleanInline(j.version, 64) : null,
        description: frame(j.description, 'package.json#description'),
        scripts: j.scripts ?? {},
        directDependencies: Object.keys(j.dependencies ?? {}).map((d) => cleanInline(d)),
        hasLockfile: hasPnpm || hasYarn || hasNpm,
        packageManager,
        entryHints,
      }
    } catch {
      /* malformed — fall through */
    }
  }

  // PyPI (pyproject.toml — light parse; no TOML dep)
  const py = await readTextContained(root, 'pyproject.toml')
  if (py) {
    const name = /^\s*name\s*=\s*["']([^"']+)["']/m.exec(py)?.[1] ?? null
    const version = /^\s*version\s*=\s*["']([^"']+)["']/m.exec(py)?.[1] ?? null
    const desc = /^\s*description\s*=\s*["']([^"']+)["']/m.exec(py)?.[1] ?? null
    return {
      ecosystem: 'pypi', name: name ? cleanInline(name) : null, version: version ? cleanInline(version, 64) : null, description: frame(desc, 'pyproject.toml#description'),
      scripts: {}, directDependencies: [], hasLockfile: (await existsContained(root, 'poetry.lock')) || (await existsContained(root, 'requirements.txt')), packageManager: (await existsContained(root, 'poetry.lock')) ? 'poetry' : 'pip', entryHints: [],
    }
  }

  // Cargo
  const cargo = await readTextContained(root, 'Cargo.toml')
  if (cargo) {
    const name = /^\s*name\s*=\s*["']([^"']+)["']/m.exec(cargo)?.[1] ?? null
    const version = /^\s*version\s*=\s*["']([^"']+)["']/m.exec(cargo)?.[1] ?? null
    const desc = /^\s*description\s*=\s*["']([^"']+)["']/m.exec(cargo)?.[1] ?? null
    return {
      ecosystem: 'cargo', name: name ? cleanInline(name) : null, version: version ? cleanInline(version, 64) : null, description: frame(desc, 'Cargo.toml#description'),
      scripts: {}, directDependencies: [], hasLockfile: await existsContained(root, 'Cargo.lock'), packageManager: 'cargo', entryHints: [],
    }
  }

  // Go
  const gomod = await readTextContained(root, 'go.mod')
  if (gomod) {
    const name = /^module\s+(\S+)/m.exec(gomod)?.[1] ?? null
    return {
      ecosystem: 'go', name: name ? cleanInline(name) : null, version: null, description: null,
      scripts: {}, directDependencies: [], hasLockfile: await existsContained(root, 'go.sum'), packageManager: 'go', entryHints: [],
    }
  }

  return null
}
