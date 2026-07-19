import { existsContained, readTextContained } from './util.js'
import { frame } from './manifest.js'
import type { ApproachPlan, BuildInfo, ManifestFacts, Permissions, RiskFinding, ScoutOptions } from './types.js'

/**
 * The APPROACH PROTOCOL — the heart of Voyager Repo. When an agent lands in an
 * unknown repo it must behave like a careful newcomer, not a bulldozer:
 *   1. Look for a Repotector presence and HANDSHAKE with it (respect its zones).
 *   2. Assume READ-ONLY. Any install / code-execution / clone is WITHHELD until
 *      explicitly consented (fail-closed) — never done silently.
 *   3. Follow an orderly orientation tour instead of poking at random.
 */
export async function planApproach(
  root: string,
  opts: ScoutOptions,
  ctx: { manifest: ManifestFacts | null; build: BuildInfo; risks: RiskFinding[]; isGitUrl: boolean },
): Promise<ApproachPlan> {
  // ── Repotector handshake ────────────────────────────────────────────────────
  // Repotector is the repo's guardian; if it is present we announce ourselves and
  // read what it will tell us (active zones/leases) — framed, since it is content.
  let repotector: ApproachPlan['repotector'] = 'absent'
  let handshake: ApproachPlan['handshake']
  if (await existsContained(root, '.repotector')) {
    repotector = 'present'
    // Contained reads: a symlinked ledger (e.g. -> ~/.ssh/id_rsa) resolves outside
    // the root and reads as absent, so a hostile repo can't exfiltrate a host file.
    const ledger =
      (await readTextContained(root, '.repotector/register.jsonl', 64 * 1024)) ??
      (await readTextContained(root, '.repotector/handshake.json', 64 * 1024)) ??
      (await readTextContained(root, '.repotector/README.md', 64 * 1024))
    const lines = ledger ? ledger.split('\n').filter(Boolean).length : 0
    handshake = {
      note: `Repotector present — handshake performed. ${lines} ledger record(s). Respect its active zones/leases before editing.`,
      framed: ledger ? (frame(ledger.slice(0, 1200), '.repotector ledger') ?? undefined) : undefined,
    }
  }

  // ── Permission model (fail-closed) ──────────────────────────────────────────
  const permissions: Permissions = {
    read: true,
    install: opts.install === true,
    exec: opts.exec === true,
    clone: opts.clone === true,
  }

  // ── What we WANTED to do but withheld pending consent ───────────────────────
  const withheld: string[] = []
  if (ctx.isGitUrl && !permissions.clone) withheld.push('clone the remote repository (needs --allow-clone)')
  if (ctx.build.install && !permissions.install) withheld.push(`install dependencies (\`${ctx.build.install}\`) — needs --allow-install`)
  if (ctx.build.test && !permissions.exec) withheld.push(`run the test suite (\`${ctx.build.test}\`) — needs --allow-exec (runs in a container)`)
  if (ctx.risks.some((r) => r.kind === 'install-hook') && !permissions.exec) {
    withheld.push('this repo has install hooks — install would execute its code; kept off until --allow-install AND a sandbox')
  }

  // ── The orderly tour: what a well-behaved agent should do next, in order ─────
  const orderedNextSteps: string[] = []
  if (repotector === 'present') orderedNextSteps.push('Honor the Repotector zones/leases surfaced above before any edit.')
  orderedNextSteps.push('Read the README (framed above) to confirm the stated purpose.')
  if (ctx.manifest?.ecosystem === 'npm' && ctx.manifest.directDependencies.length) {
    orderedNextSteps.push('Vet the direct dependencies with Voyager before installing (voyager-repo --check-deps N).')
  }
  orderedNextSteps.push('Open the detected entrypoint(s) to trace the main flow.')
  if (ctx.build.test) orderedNextSteps.push(`Run the tests IN A SANDBOX (${ctx.build.test}) to learn the expected behavior — only after --allow-exec.`)
  const highRisks = ctx.risks.filter((r) => r.level === 'high')
  if (highRisks.length) orderedNextSteps.push(`Resolve the ${highRisks.length} HIGH-risk finding(s) before trusting or installing this repo.`)

  return { repotector, handshake, permissions, withheld, orderedNextSteps }
}
