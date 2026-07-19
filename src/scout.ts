import { resolve } from 'node:path'
import { checkPackage } from '@dir-ai/voyager'
import { walkRepo, exists } from './util.js'
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

  // A remote URL cannot be oriented without cloning — which is consent-gated.
  if (isGitUrl && opts.clone !== true) {
    const b = base()
    b.summary = `Remote repository — orientation needs a clone (consent-gated).`
    b.approach = await planApproach(process.cwd(), opts, { manifest: null, build: b.build, risks: [], isGitUrl: true })
    b.notes.push('Pass --allow-clone to fetch and orient, or point Pathfinder at a local checkout.')
    b.suggestedNextProbe.push('git clone the repo to a scratch dir, then re-run Pathfinder on the local path.')
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
    const toCheck = manifest.directDependencies.slice(0, checkN)
    for (const name of toCheck) {
      try {
        const est = await checkPackage({ name, ecosystem: 'npm' })
        dependencies.findings.push({ name, verdict: est.error ? 'unknown' : est.verdict, note: est.error ?? est.claim?.warning })
      } catch (e) {
        dependencies.findings.push({ name, verdict: 'unknown', note: (e as Error)?.message?.slice(0, 120) })
      }
      dependencies.checked++
    }
    dependencies.coverage = dependencies.checked >= dependencies.direct ? 'direct' : 'sampled'
    for (const f of dependencies.findings) if (f.verdict === 'rejected') risks.push({ level: 'high', kind: 'unsafe-dependency', detail: `dependency ${f.name} is REJECTED by Voyager: ${f.note ?? 'unsafe'}` })
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
