import { test } from 'node:test'
import assert from 'node:assert/strict'
import { adaptTrivy, adaptSemgrep, wrapScanners } from '../dist/index.js'

test('adaptTrivy: maps vulnerabilities / secrets / misconfigs into framed findings', () => {
  const trivy = {
    Results: [
      { Target: 'package-lock.json', Vulnerabilities: [{ VulnerabilityID: 'CVE-2021-44906', PkgName: 'minimist', InstalledVersion: '1.2.5', FixedVersion: '1.2.6', Severity: 'HIGH' }] },
      { Target: 'main.tf', Misconfigurations: [{ ID: 'AVD-AWS-0086', Title: 'S3 bucket is public', Severity: 'CRITICAL' }] },
      { Target: '.env', Secrets: [{ RuleID: 'aws-access-key', Title: 'AWS Access Key', StartLine: 3 }] },
    ],
  }
  const f = adaptTrivy(trivy)
  assert.ok(f.some((x) => x.kind === 'trivy-vuln' && /CVE-2021-44906/.test(x.detail) && x.level === 'high'))
  assert.ok(f.some((x) => x.kind === 'trivy-misconfig' && /S3 bucket is public/.test(x.detail) && x.level === 'high'))
  assert.ok(f.some((x) => x.kind === 'trivy-secret' && x.level === 'high'))
})

test('adaptSemgrep: maps results into framed findings with normalized severity', () => {
  const semgrep = { results: [{ check_id: 'javascript.lang.security.eval', path: 'src/index.js', extra: { severity: 'ERROR', message: 'Detected eval() with user input' } }] }
  const f = adaptSemgrep(semgrep)
  assert.equal(f.length, 1)
  assert.equal(f[0].kind, 'semgrep')
  assert.equal(f[0].level, 'high')
  assert.match(f[0].detail, /eval/)
})

test('adaptTrivy/adaptSemgrep: garbage input yields no findings, never throws', () => {
  assert.deepEqual(adaptTrivy(null), [])
  assert.deepEqual(adaptTrivy({ Results: 'nope' }), [])
  assert.deepEqual(adaptSemgrep(undefined), [])
})

test('wrapScanners: honestly reports missing engines (no false clean)', async () => {
  const { notes } = await wrapScanners(process.cwd())
  // On a box without trivy/semgrep, it must SAY they are missing, not stay silent.
  assert.ok(notes.some((n) => /deeper coverage available|wrapped external engines/.test(n)), notes.join(' | '))
})
