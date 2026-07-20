import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { cleanInline } from './manifest.js'
import type { RiskFinding } from './types.js'

const pExecFile = promisify(execFile)

/**
 * WRAP, DON'T REBUILD — the strategic core. The world's best coverage engines already
 * exist (Trivy: CVE+IaC+secrets+SBOM; Semgrep: SAST; trufflehog: history secrets;
 * osv-scanner: transitive deps). Voyager does NOT re-implement them — it WRAPS them
 * as a sense: runs each ONLY if it's on PATH, bounded + read-only, then adapts its
 * output into framed, injection-stripped RiskFindings under the SAME gate as every
 * other sense. So an agent gets the engine's coverage AND the trust contract that no
 * engine has on its own. If a tool is absent, we say so honestly (a note, never a
 * false "clean") — installing it deepens coverage without changing the interface.
 */
const NORM_LEVEL: Record<string, RiskFinding['level']> = {
  CRITICAL: 'high', HIGH: 'high', ERROR: 'high', MEDIUM: 'medium', WARNING: 'medium', MODERATE: 'medium', LOW: 'low', INFO: 'info', UNKNOWN: 'info',
}
const lvl = (s: string | undefined): RiskFinding['level'] => NORM_LEVEL[(s ?? '').toUpperCase()] ?? 'info'

/** Adapt Trivy's `--format json` fs report into framed findings. Pure + testable. */
export function adaptTrivy(json: unknown): RiskFinding[] {
  const out: RiskFinding[] = []
  const results = (json as { Results?: unknown[] })?.Results
  if (!Array.isArray(results)) return out
  for (const r of results as Array<Record<string, unknown>>) {
    const at = cleanInline(String(r.Target ?? ''), 120)
    for (const v of (Array.isArray(r.Vulnerabilities) ? r.Vulnerabilities : []) as Array<Record<string, unknown>>) {
      out.push({ level: lvl(v.Severity as string), kind: 'trivy-vuln', detail: `[trivy] ${cleanInline(String(v.VulnerabilityID ?? 'CVE'), 40)} in ${cleanInline(String(v.PkgName ?? ''), 60)}@${cleanInline(String(v.InstalledVersion ?? ''), 40)}${v.FixedVersion ? ` (fixed in ${cleanInline(String(v.FixedVersion), 40)})` : ''}`, path: at })
    }
    for (const s of (Array.isArray(r.Secrets) ? r.Secrets : []) as Array<Record<string, unknown>>) {
      out.push({ level: 'high', kind: 'trivy-secret', detail: `[trivy] secret "${cleanInline(String(s.Title ?? s.RuleID ?? 'secret'), 60)}" at ${at}:${s.StartLine ?? '?'}`, path: at })
    }
    for (const m of (Array.isArray(r.Misconfigurations) ? r.Misconfigurations : []) as Array<Record<string, unknown>>) {
      out.push({ level: lvl(m.Severity as string), kind: 'trivy-misconfig', detail: `[trivy] misconfig ${cleanInline(String(m.ID ?? ''), 30)}: ${cleanInline(String(m.Title ?? ''), 120)}`, path: at })
    }
  }
  return out
}

/** Adapt Semgrep's `--json` output into framed findings. Pure + testable. */
export function adaptSemgrep(json: unknown): RiskFinding[] {
  const out: RiskFinding[] = []
  const results = (json as { results?: unknown[] })?.results
  if (!Array.isArray(results)) return out
  for (const r of results as Array<Record<string, unknown>>) {
    const extra = (r.extra ?? {}) as Record<string, unknown>
    const sev = ((extra.severity as string) ?? 'INFO').toUpperCase()
    out.push({ level: lvl(sev), kind: 'semgrep', detail: `[semgrep] ${cleanInline(String(r.check_id ?? 'rule'), 60)}: ${cleanInline(String(extra.message ?? ''), 120)}`, path: cleanInline(String(r.path ?? ''), 120) })
  }
  return out
}

async function onPath(cmd: string, versionArg = '--version'): Promise<boolean> {
  try {
    await pExecFile(cmd, [versionArg], { timeout: 5000 })
    return true
  } catch {
    return false
  }
}

/**
 * Run whichever wrapped engines are installed against the repo, adapt their output,
 * and return findings + an honest coverage note. Bounded (timeouts, maxBuffer) and
 * read-only. Absence of a tool is reported, never hidden.
 */
export async function wrapScanners(root: string): Promise<{ findings: RiskFinding[]; notes: string[] }> {
  const findings: RiskFinding[] = []
  const notes: string[] = []
  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' }
  const available: string[] = []
  const missing: string[] = []

  if (await onPath('trivy')) {
    available.push('trivy')
    try {
      const { stdout } = await pExecFile('trivy', ['fs', '--quiet', '--format', 'json', '--scanners', 'vuln,secret,misconfig', '--timeout', '90s', root], { timeout: 120_000, maxBuffer: 16 << 20, env })
      findings.push(...adaptTrivy(JSON.parse(stdout)))
    } catch (e) {
      notes.push(`trivy present but the scan did not complete: ${cleanInline((e as Error)?.message ?? '', 100)}`)
    }
  } else missing.push('trivy (CVE/IaC/secret/SBOM)')

  if (await onPath('semgrep')) {
    available.push('semgrep')
    try {
      const { stdout } = await pExecFile('semgrep', ['--json', '--quiet', '--config', 'auto', '--timeout', '90', root], { timeout: 150_000, maxBuffer: 16 << 20, env })
      findings.push(...adaptSemgrep(JSON.parse(stdout)))
    } catch (e) {
      notes.push(`semgrep present but the scan did not complete: ${cleanInline((e as Error)?.message ?? '', 100)}`)
    }
  } else missing.push('semgrep (SAST/code)')

  if (available.length) notes.push(`wrapped external engines: ${available.join(', ')} — their findings are framed + gated like every Voyager sense`)
  if (missing.length) notes.push(`deeper coverage available if installed (Voyager will wrap them under the same gate): ${missing.join(', ')}`)
  return { findings, notes }
}
