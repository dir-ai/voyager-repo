#!/usr/bin/env node
/**
 * voyager-repo CLI — orient in an unknown repository, safely.
 */
import { scout } from './scout.js'
import { VERSION } from './version.js'
import type { OrientationBrief, ScoutOptions } from './types.js'

function parseArgs(argv: string[]): { flags: Record<string, string | boolean>; positionals: string[] } {
  const boolean = new Set(['json', 'allow-install', 'allow-exec', 'allow-clone'])
  const flags: Record<string, string | boolean> = {}
  const positionals: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      const key = a.slice(2)
      const next = argv[i + 1]
      if (!boolean.has(key) && next !== undefined && !next.startsWith('--')) { flags[key] = next; i++ }
      else flags[key] = true
    } else positionals.push(a)
  }
  return { flags, positionals }
}

const HELP = `voyager-repo v${VERSION} — Voyager's repo organ: an agent's safe scout

USAGE
  voyager-repo scout [path] [--check-deps N] [--allow-install] [--allow-exec]
                          [--allow-clone] [--max-files N] [--json]
        Orient in the repo at [path] (default: current dir). READ-ONLY: maps
        purpose/structure/build/health/risks, frames all owner text as untrusted,
        vets up to N dependencies via Voyager, handshakes with Repotector if
        present, and WITHHOLDS install/exec/clone until you consent.
        Exit: 0 oriented · 1 oriented + HIGH-risk finding(s) · 2 tool error.

  voyager-repo mcp                  Start the stdio MCP server (tool: scout_repo).
  voyager-repo help | --version

Nothing in the target is ever executed on the host. Consent flags gate invasive
steps; execution (when allowed) belongs in a sandbox.`

const GLYPH: Record<string, string> = { high: '⛔', medium: '⚠', low: '·', info: 'ℹ' }

function render(b: OrientationBrief): void {
  if (b.error) {
    console.error(`✗ could not orient: ${b.error}`)
    return
  }
  console.log(`\n${b.summary}`)
  console.log(`  confidence: ${b.confidence} · ${b.sanitization.framedFields} framed field(s), ${b.sanitization.strippedPayloads} payload(s) stripped`)

  if (b.structure) {
    const langs = Object.entries(b.structure.languages).slice(0, 4).map(([l, n]) => `${l} ${n}`).join(', ')
    console.log(`\nstructure: ${b.structure.fileCount} files${b.structure.truncated ? '+ (truncated)' : ''} · ${langs || 'n/a'}`)
    if (b.structure.keyDirs.length) console.log(`  dirs: ${b.structure.keyDirs.map((d) => `${d.path}(${d.role})`).join(', ')}`)
    if (b.structure.entrypoints.length) console.log(`  entrypoints: ${b.structure.entrypoints.join(', ')}`)
  }
  const cmds = [b.build.install && `install: ${b.build.install}`, b.build.test && `test: ${b.build.test}`, b.build.run && `run: ${b.build.run}`].filter(Boolean)
  if (cmds.length) console.log(`\nbuild: ${cmds.join(' · ')}`)

  if (b.health.isGitRepo) {
    const bus = b.health.topAuthorShare != null ? `, top author ${Math.round(b.health.topAuthorShare * 100)}%` : ''
    console.log(`\nhealth: ${b.health.commits ?? '?'} commits, ${b.health.contributors ?? '?'} contributor(s)${bus}, last ${b.health.lastCommitISO?.slice(0, 10) ?? '?'}`)
    if (b.health.hotspots.length) console.log(`  hotspots: ${b.health.hotspots.slice(0, 3).join(', ')}`)
  }

  if (b.dependencies.checked > 0) {
    const rej = b.dependencies.findings.filter((f) => f.verdict === 'rejected').map((f) => f.name)
    console.log(`\ndependencies: ${b.dependencies.direct} direct, ${b.dependencies.checked} vetted (${b.dependencies.coverage})${rej.length ? ` · REJECTED: ${rej.join(', ')}` : ' · none rejected'}`)
  } else if (b.dependencies.direct > 0) {
    console.log(`\ndependencies: ${b.dependencies.direct} direct (not vetted — pass --check-deps N)`)
  }

  if (b.risks.length) {
    console.log(`\nrisks:`)
    for (const r of b.risks.slice(0, 12)) console.log(`  ${GLYPH[r.level] ?? '·'} [${r.level}] ${r.kind}: ${r.detail}`)
  }

  console.log(`\napproach:`)
  console.log(`  Repotector: ${b.approach.repotector}${b.approach.handshake ? ` — ${b.approach.handshake.note}` : ''}`)
  console.log(`  permissions: read✓ install${b.approach.permissions.install ? '✓' : '✗'} exec${b.approach.permissions.exec ? '✓' : '✗'} clone${b.approach.permissions.clone ? '✓' : '✗'}`)
  for (const w of b.approach.withheld) console.log(`  withheld: ${w}`)
  if (b.approach.orderedNextSteps.length) {
    console.log(`  orderly next steps:`)
    b.approach.orderedNextSteps.forEach((s, i) => console.log(`    ${i + 1}. ${s}`))
  }
  if (b.notes.length) for (const n of b.notes) console.log(`\nnote: ${n}`)
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2)
  const { flags, positionals } = parseArgs(rest)
  const json = flags.json === true

  switch (cmd) {
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      console.log(HELP)
      return 0
    case '--version':
    case 'version':
      console.log(VERSION)
      return 0

    case 'scout': {
      const opts: ScoutOptions = {
        checkDeps: typeof flags['check-deps'] === 'string' ? Number(flags['check-deps']) || 0 : 0,
        install: flags['allow-install'] === true,
        exec: flags['allow-exec'] === true,
        clone: flags['allow-clone'] === true,
        maxFiles: typeof flags['max-files'] === 'string' ? Number(flags['max-files']) || undefined : undefined,
        onLog: (l) => { if (!json) console.error(`  · ${l}`) },
      }
      const b = await scout(positionals[0] ?? '.', opts)
      if (json) console.log(JSON.stringify(b, null, 2))
      else render(b)
      if (b.error) return 2
      return b.risks.some((r) => r.level === 'high') ? 1 : 0
    }

    case 'mcp': {
      const { startMcpServer } = await import('./mcp.js')
      await startMcpServer()
      return new Promise<number>(() => {})
    }

    default:
      console.error(`Unknown command: ${cmd}\n`)
      console.log(HELP)
      return 2
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err instanceof Error ? (err.stack ?? err.message) : String(err))
    process.exit(2)
  })
