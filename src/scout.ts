import { resolve } from 'node:path'
import { checkPackage } from '@dir-ai/voyager'
import { walkRepo, exists, readTextContained } from './util.js'
import { scanManifest } from './manifest.js'
import { scanStructure } from './structure.js'
import { inferBuild } from './build.js'
import { scanHealth } from './health.js'
import { scanRisks } from './risks.js'
import { planApproach } from './approach.js'
import type { Confidence, DependencyPosture, OrientationBrief, ScoutOptions } from './types.js'

const GIT_URL = /^(https?:\/\/|git@|ssh:\/\/|git:\/\/).+/i

/**
 * Orient in an unknown repository — the agent's proactive scout. READ-ONLY: walks
 * files and git, frames all owner text, composes with Voyager to vet dependencies,
 * and returns an orientation brief plus an approach plan. Never installs, executes,
 * or clones unless explicitly permitted (and even then only in a sandbox).
 */
export async function scout(input: string, opts: ScoutOptions = {}): Promise<OrientationBrief> {
  const log = opts.onLog ?? (() => {})
  const isGitUrl = GIT_URL.test(input)
  const maxFiles = opts.maxFiles ?? 4000

  const base = (): OrientationBrief => ({
    target: { input, kind: isGitUrl ? 'git-url' : 'local', resolvedPath: null },
    summary: '', purpose: null, manifest: null, structure: null,
    build: { install: null, build: null, test: null, run: null, packageManager: null },
    dependencies: { direct: 0, checked: 0, coverage: 'none', findings: [] },
    health: { isGitRepo: false, commits: null, contributors: null, topAuthorShare: null, lastCommitISO: null, hotspots: [], archivedHint: false },
    risks: [], approach: { repotector: 'absent', permissions: { read: true, install: false, exec: false, clone: false }, withheld: [], orderedNextSteps: [] },
    confidence: 'weak', sanitization: { framedFields: 0, strippedPayloads: 0 }, suggestedNextProbe: [], notes: [],
  })

  // A remote URL cannot be oriented without cloning — which is consent-gated. Do
  // NOT run a filesystem approach plan against the CWD here (it would scan the
  // AGENT'S OWN directory for .repotector and surface an unrelated handshake).
  if (isGitUrl && opts.clone !== true) {
    const b = base()
    b.summary = `Remote repository — orientation needs a clone (consent-gated). Cloning is not yet implemented; use a local checkout.`
    b.approach = {
      repotector: 'absent',
      permissions: { read: true, install: false, exec: false, clone: false },
      withheld: ['clone the remote repository (not yet implemented — use a local checkout)'],
      orderedNextSteps: ['obtain a local checkout of the repo', 'run voyager-repo scout on the local path'],
    }
    b.notes.push('Remote clone-and-orient is not implemented yet — git clone to a scratch dir and point Voyager Repo at the local path.')
    b.suggestedNextProbe.push('git clone the repo to a scratch dir, then re-run Voyager Repo on the local path.')
    return b
  }

  const root = resolve(input)
  if (!(await exists(root))) {
    return { ...base(), error: `path not found: ${input}` }
  }

  log('reading manifest…')
  const manifest = await scanManifest(root)
  log('mapping structure…')
  const structure = await scanStructure(root, maxFiles, manifest)
  const build = inferBuild(manifest)
  log('reading git history…')
  const health = await scanHealth(root)
  const { files } = await walkRepo(root, maxFiles)
  log('scanning risk surfaces…')
  const risks = await scanRisks(root, manifest, structure, files)

  // ── Dependency posture — compose with Voyager (opt-in, bounded) ─────────────
  const dependencies: DependencyPosture = { direct: manifest?.directDependencies.length ?? 0, checked: 0, coverage: 'none', findings: [] }
  const checkN = Math.min(opts.checkDeps ?? 0, 20)
  if (checkN > 0 && manifest?.ecosystem === 'npm' && manifest.directDependencies.length) {
    log(`vetting ${Math.min(checkN, manifest.directDependencies.length)} dependencies via Voyager…`)
    // Vet the EXACT version the lockfile pins, not the latest registry version — a
    // repo locked to a vulnerable version must not read clean because the latest
    // one is fine (Codex's repo P0). AND walk the TRANSITIVE tree from the lockfile,
    // not just the direct deps (Kimi #5: a vulnerable minimist buried transitively
    // is where real supply-chain risk hides). Both bounded so a huge lockfile can't
    // fan out unboundedly.
    const locked = await lockedVersions(root)
    const directSet = new Set(manifest.directDependencies)
    const transCap = Math.min(40, checkN * 5)
    const toVet: Array<{ name: string; version?: string; direct: boolean }> = manifest.directDependencies.slice(0, checkN).map((name) => ({ name, version: locked[name], direct: true }))
    for (const [name, version] of Object.entries(locked)) {
      if (directSet.has(name)) continue
      if (toVet.length >= checkN + transCap) break
      toVet.push({ name, version, direct: false })
    }
    let transitiveChecked = 0
    for (const { name, version, direct } of toVet) {
      const label = version ? `${name}@${version}` : name
      try {
        const est = await checkPackage({ name, ecosystem: 'npm', version })
        dependencies.findings.push({ name: label, verdict: est.error ? 'unknown' : est.verdict, note: `${direct ? '' : '(transitive) '}${est.error ?? est.claim?.warning ?? ''}`.trim() || undefined })
      } catch (e) {
        dependencies.findings.push({ name: label, verdict: 'unknown', note: `${direct ? '' : '(transitive) '}${(e as Error)?.message?.slice(0, 120) ?? ''}`.trim() || undefined })
      }
      dependencies.checked++
      if (!direct) transitiveChecked++
    }
    dependencies.coverage = transitiveChecked > 0 ? 'tree' : dependencies.checked >= dependencies.direct ? 'direct' : 'sampled'
    for (const f of dependencies.findings) {
      if (f.verdict !== 'rejected') continue
      const transitive = /\(transitive\)/.test(f.note ?? '')
      risks.push({ level: 'high', kind: transitive ? 'unsafe-transitive-dependency' : 'unsafe-dependency', detail: `${transitive ? 'transitive ' : ''}dependency ${f.name} is REJECTED by Voyager: ${(f.note ?? 'unsafe').replace('(transitive) ', '')}` })
    }
  }

  const approach = await planApproach(root, opts, { manifest, build, risks, isGitUrl: false })

  // ── Summary + confidence + sanitization ─────────────────────────────────────
  const purpose = manifest?.description ?? null
  const name = manifest?.name ?? root.split(/[\\/]/).pop() ?? 'repository'
  const langTop = structure ? Object.keys(structure.languages)[0] : null
  const summary =
    purpose?.framed
      ? `${name}${manifest?.version ? `@${manifest.version}` : ''} — ${purpose.framed.split('\n')[0].slice(0, 160)}`
      : `${name} — a ${langTop ?? 'code'} repository${manifest ? ` (${manifest.ecosystem})` : ''}; purpose not declared, infer from the entrypoints.`

  const framedFields = [purpose, approach.handshake?.framed].filter(Boolean).length
  const strippedPayloads = (purpose?.stripped ?? 0) + (approach.handshake?.framed?.stripped ?? 0)

  let confidence: Confidence = 'weak'
  const signals = [Boolean(manifest), health.isGitRepo, Boolean(purpose), (structure?.fileCount ?? 0) > 3].filter(Boolean).length
  confidence = signals >= 3 ? 'strong' : signals === 2 ? 'moderate' : 'weak'

  const suggestedNextProbe: string[] = []
  if (structure?.entrypoints.length) suggestedNextProbe.push(`open ${structure.entrypoints[0]}`)
  if (health.hotspots.length) suggestedNextProbe.push(`review churn hotspot ${health.hotspots[0].split(' ')[0]}`)
  if (!purpose) suggestedNextProbe.push('read README / docs to confirm purpose')
  if (dependencies.direct > dependencies.checked) suggestedNextProbe.push(`vet the remaining ${dependencies.direct - dependencies.checked} dependencies (--check-deps)`)

  return {
    target: { input, kind: 'local', resolvedPath: root },
    summary, purpose, manifest, structure, build, dependencies, health, risks, approach,
    confidence, sanitization: { framedFields, strippedPayloads }, suggestedNextProbe, notes: [],
  }
}

/** Resolve EXACT installed versions from package-lock.json so dependency vetting
 *  probes what is actually pinned (lockfileVersion 1 flat map, and 2/3 keyed by
 *  node_modules paths). Malformed lock → empty map (vetting falls back to latest). */
async function lockedVersions(root: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {}
  const lock = await readTextContained(root, 'package-lock.json')
  if (!lock) return out
  try {
    const j = JSON.parse(lock) as { packages?: Record<string, { version?: string }>; dependencies?: Record<string, { version?: string }> }
    for (const [k, v] of Object.entries(j.packages ?? {})) {
      const m = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(k)
      if (m && typeof v?.version === 'string' && !out[m[1]]) out[m[1]] = v.version
    }
    for (const [name, v] of Object.entries(j.dependencies ?? {})) if (typeof v?.version === 'string' && !out[name]) out[name] = v.version
  } catch {
    /* malformed lockfile → no pinned versions */
  }
  return out
}
