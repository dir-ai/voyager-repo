import { join } from 'node:path'
import { stripInjection } from '@dir-ai/voyager'
import { readTextCapped, exists } from './util.js'
import type { ManifestFacts, FramedText } from './types.js'

/** Build a FramedText: injection-stripped, with a count of what was removed. */
export function frame(raw: string | null | undefined, source: string): FramedText | null {
  if (!raw) return null
  const trimmed = raw.trim()
  if (!trimmed) return null
  const framed = stripInjection(trimmed)
  // A payload was present if stripping changed the text (markers/removals appear).
  const stripped = framed === trimmed ? 0 : 1
  return { framed: framed.slice(0, 600), stripped, source }
}

/** Detect the ecosystem and read its manifest into normalized facts. Owner text
 *  (description) is FRAMED — never returned raw. */
export async function scanManifest(root: string): Promise<ManifestFacts | null> {
  // npm
  const pj = await readTextCapped(join(root, 'package.json'))
  if (pj) {
    try {
      const j = JSON.parse(pj) as {
        name?: string; version?: string; description?: string
        scripts?: Record<string, string>
        dependencies?: Record<string, string>; peerDependencies?: Record<string, string>
      }
      const hasLock = (await exists(join(root, 'package-lock.json'))) || (await exists(join(root, 'pnpm-lock.yaml'))) || (await exists(join(root, 'yarn.lock')))
      return {
        ecosystem: 'npm',
        name: j.name ?? null,
        version: j.version ?? null,
        description: frame(j.description, 'package.json#description'),
        scripts: j.scripts ?? {},
        directDependencies: Object.keys(j.dependencies ?? {}),
        hasLockfile: hasLock,
      }
    } catch {
      /* malformed — fall through */
    }
  }

  // PyPI (pyproject.toml — light parse; no TOML dep)
  const py = await readTextCapped(join(root, 'pyproject.toml'))
  if (py) {
    const name = /^\s*name\s*=\s*["']([^"']+)["']/m.exec(py)?.[1] ?? null
    const version = /^\s*version\s*=\s*["']([^"']+)["']/m.exec(py)?.[1] ?? null
    const desc = /^\s*description\s*=\s*["']([^"']+)["']/m.exec(py)?.[1] ?? null
    return {
      ecosystem: 'pypi', name, version, description: frame(desc, 'pyproject.toml#description'),
      scripts: {}, directDependencies: [], hasLockfile: (await exists(join(root, 'poetry.lock'))) || (await exists(join(root, 'requirements.txt'))),
    }
  }

  // Cargo
  const cargo = await readTextCapped(join(root, 'Cargo.toml'))
  if (cargo) {
    const name = /^\s*name\s*=\s*["']([^"']+)["']/m.exec(cargo)?.[1] ?? null
    const version = /^\s*version\s*=\s*["']([^"']+)["']/m.exec(cargo)?.[1] ?? null
    const desc = /^\s*description\s*=\s*["']([^"']+)["']/m.exec(cargo)?.[1] ?? null
    return {
      ecosystem: 'cargo', name, version, description: frame(desc, 'Cargo.toml#description'),
      scripts: {}, directDependencies: [], hasLockfile: await exists(join(root, 'Cargo.lock')),
    }
  }

  // Go
  const gomod = await readTextCapped(join(root, 'go.mod'))
  if (gomod) {
    const name = /^module\s+(\S+)/m.exec(gomod)?.[1] ?? null
    return {
      ecosystem: 'go', name, version: null, description: null,
      scripts: {}, directDependencies: [], hasLockfile: await exists(join(root, 'go.sum')),
    }
  }

  return null
}
