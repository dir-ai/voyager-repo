import { join } from 'node:path'
import { promises as fs } from 'node:fs'
import { readTextCapped } from './util.js'
import type { ManifestFacts, RiskFinding, StructureMap } from './types.js'

// Secret-shaped patterns (high-confidence, low false-positive). NOT exhaustive —
// a signal for the agent, not a secret scanner.
// PEM patterns require the FULL block (header + a real base64 body + END) so a
// security tool that merely DEFINES these patterns as strings doesn't self-match.
const SECRET_PATTERNS: Array<{ re: RegExp; what: string }> = [
  { re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\r\n]{40,}-----END/, what: 'private key' },
  { re: /-----BEGIN CERTIFICATE-----[\r\n]+[A-Za-z0-9+/=\r\n]{40,}-----END CERTIFICATE-----/, what: 'certificate' },
  { re: /\bAKIA[0-9A-Z]{16}\b/, what: 'AWS access key id' },
  { re: /\bghp_[A-Za-z0-9]{36}\b/, what: 'GitHub personal access token' },
  { re: /\bxox[baprs]-[0-9]{6,}-[A-Za-z0-9-]{10,}\b/, what: 'Slack token' },
]

const SUSPICIOUS_FILES = new Set(['.env', '.env.local', '.env.production', 'id_rsa', 'id_dsa', 'id_ecdsa', '.npmrc', '.pypirc', 'credentials', '.aws/credentials'])

/** Assess supply-chain / hygiene risk surfaces (read-only, bounded). */
export async function scanRisks(root: string, manifest: ManifestFacts | null, structure: StructureMap | null, files: string[]): Promise<RiskFinding[]> {
  const risks: RiskFinding[] = []

  // 1) npm lifecycle install hooks — code that runs on `npm install` (RCE vector).
  const s = manifest?.scripts ?? {}
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
    if (s[hook]) {
      risks.push({ level: 'high', kind: 'install-hook', detail: `runs on install → "${hook}": ${s[hook].slice(0, 80)}`, path: 'package.json' })
    }
  }

  // 2) Missing lockfile — non-reproducible install (drift/supply-chain surface).
  if (manifest && manifest.ecosystem !== 'go' && !manifest.hasLockfile) {
    risks.push({ level: 'low', kind: 'no-lockfile', detail: 'no lockfile — installed versions are not pinned/reproducible' })
  }

  // 3) Committed secret-bearing files by name.
  for (const f of files) {
    const base = f.split('/').pop() ?? f
    if (SUSPICIOUS_FILES.has(base)) {
      risks.push({ level: base.startsWith('.env') ? 'medium' : 'high', kind: 'sensitive-file', detail: `sensitive file committed: ${f}`, path: f })
    }
  }

  // 4) Secret PATTERNS in a bounded sample of small text files.
  const textish = files
    .filter((f) => /\.(env|txt|json|ya?ml|toml|md|js|ts|py|sh|cfg|ini|pem|key)$/i.test(f) || !f.includes('.'))
    .slice(0, 400)
  let scanned = 0
  for (const rel of textish) {
    if (scanned >= 200) break
    const content = await readTextCapped(join(root, rel), 128 * 1024)
    if (content == null) continue
    scanned++
    for (const { re, what } of SECRET_PATTERNS) {
      if (re.test(content)) {
        risks.push({ level: 'high', kind: 'hardcoded-secret', detail: `possible ${what} in ${rel}`, path: rel })
        break
      }
    }
  }

  // 5) Large binaries — opaque surface an agent should not blindly trust/execute.
  let bigCount = 0
  for (const rel of files.slice(0, 2000)) {
    if (bigCount >= 3) break
    try {
      const st = await fs.stat(join(root, rel))
      if (st.size > 5 * 1024 * 1024) {
        risks.push({ level: 'info', kind: 'large-file', detail: `${rel} (${Math.round(st.size / 1048576)}MB)`, path: rel })
        bigCount++
      }
    } catch {
      /* ignore */
    }
  }

  return risks
}
