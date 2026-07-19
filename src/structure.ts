import { walkRepo } from './util.js'
import type { StructureMap, ManifestFacts } from './types.js'

const EXT_LANG: Record<string, string> = {
  ts: 'TypeScript', tsx: 'TypeScript', js: 'JavaScript', jsx: 'JavaScript', mjs: 'JavaScript', cjs: 'JavaScript',
  py: 'Python', rs: 'Rust', go: 'Go', java: 'Java', kt: 'Kotlin', rb: 'Ruby', php: 'PHP', cs: 'C#',
  c: 'C', h: 'C', cpp: 'C++', cc: 'C++', hpp: 'C++', swift: 'Swift', scala: 'Scala', ex: 'Elixir', exs: 'Elixir',
  sh: 'Shell', ps1: 'PowerShell', sql: 'SQL', html: 'HTML', css: 'CSS', scss: 'CSS', vue: 'Vue', svelte: 'Svelte',
  md: 'Docs', mdx: 'Docs', json: 'Config', yaml: 'Config', yml: 'Config', toml: 'Config',
}

const DIR_ROLE: Record<string, string> = {
  src: 'source', lib: 'source', app: 'application', pkg: 'packages', packages: 'packages (monorepo?)',
  test: 'tests', tests: 'tests', __tests__: 'tests', spec: 'tests', e2e: 'end-to-end tests',
  docs: 'documentation', doc: 'documentation', examples: 'examples', example: 'examples',
  scripts: 'scripts', bin: 'executables', tools: 'tooling', config: 'configuration',
  public: 'static assets', assets: 'assets', dist: 'build output', '.github': 'CI/CD + repo config',
  api: 'API surface', server: 'server', client: 'client', migrations: 'DB migrations', db: 'database',
}

const ENTRY_CANDIDATES = ['index.ts', 'index.js', 'main.ts', 'main.js', 'src/index.ts', 'src/index.js', 'src/main.ts', 'src/main.rs', 'main.py', '__main__.py', 'main.go', 'cmd/main.go', 'app.py', 'server.ts', 'server.js']

/** Map the repo's shape from a bounded walk: languages, key dirs, entrypoints. */
export async function scanStructure(root: string, maxFiles: number, manifest: ManifestFacts | null): Promise<StructureMap> {
  const { files, dirs, truncated } = await walkRepo(root, maxFiles)

  const langCount: Record<string, number> = {}
  const present = new Set(files)
  for (const f of files) {
    const ext = f.includes('.') ? f.slice(f.lastIndexOf('.') + 1).toLowerCase() : ''
    const lang = EXT_LANG[ext]
    if (lang) langCount[lang] = (langCount[lang] ?? 0) + 1
  }
  const languages = Object.fromEntries(Object.entries(langCount).sort((a, b) => b[1] - a[1]))

  const keyDirs = dirs
    .map((d) => ({ path: d, role: DIR_ROLE[d] ?? 'unclassified' }))
    .sort((a, b) => (a.role === 'unclassified' ? 1 : 0) - (b.role === 'unclassified' ? 1 : 0))

  // Entrypoints: manifest bin/main first (authoritative), then conventional files.
  const entrypoints: string[] = []
  const push = (p: string | undefined | null) => {
    if (p && present.has(p) && !entrypoints.includes(p)) entrypoints.push(p)
  }
  if (manifest?.ecosystem === 'npm') {
    // main/bin are read separately in manifest scan; conventional fallbacks here.
  }
  for (const c of ENTRY_CANDIDATES) push(c)

  return { root, fileCount: files.length, truncated, languages, keyDirs, entrypoints }
}
