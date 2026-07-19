import { test } from 'node:test'
import assert from 'node:assert/strict'
import { promises as fs } from 'node:fs'
import { mkdtemp, writeFile, mkdir, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { scout } from '../dist/index.js'
import { readTextContained, readTextCapped } from '../dist/util.js'
import { mkRepo } from './_fixtures.js'

test('M5: pnpm/yarn lockfiles yield the right install command (not always npm)', async () => {
  const pnpm = await mkRepo({ 'package.json': { name: 'x', version: '1.0.0' }, 'pnpm-lock.yaml': 'lockfileVersion: 6' })
  const b = await scout(pnpm)
  assert.equal(b.build.packageManager, 'pnpm')
  assert.equal(b.build.install, 'pnpm install')

  const yarn = await mkRepo({ 'package.json': { name: 'y', version: '1.0.0' }, 'yarn.lock': '# yarn' })
  assert.equal((await scout(yarn)).build.install, 'yarn install')
})

test('H1: a read is byte-bounded — a large file is NOT fully buffered into the result', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vr-big-'))
  const big = join(dir, 'big.txt')
  await writeFile(big, 'x'.repeat(1_000_000)) // 1 MB
  const got = await readTextCapped(big, 4096)
  assert.ok(got != null && got.length <= 4096, `expected ≤4096 bytes, got ${got?.length}`)
})

test('H2: readTextContained refuses a symlink that escapes the repo root', async () => {
  const root = await mkdtemp(join(tmpdir(), 'vr-root-'))
  const outside = await mkdtemp(join(tmpdir(), 'vr-secret-'))
  const secretPath = join(outside, 'secret.txt')
  await writeFile(secretPath, 'TOP-SECRET-HOST-FILE')
  await mkdir(join(root, '.repotector'), { recursive: true })
  let symlinked = true
  try {
    await symlink(secretPath, join(root, '.repotector', 'register.jsonl'))
  } catch {
    symlinked = false // Windows without privilege — skip the assertion
  }
  if (!symlinked) return
  const leaked = await readTextContained(root, '.repotector/register.jsonl')
  assert.equal(leaked, null, 'a symlink escaping the root must read as null, never leak the host file')
  // And a legitimate in-root file still reads fine.
  await writeFile(join(root, '.repotector', 'handshake.json'), '{"ok":true}')
  assert.match((await readTextContained(root, '.repotector/handshake.json')) ?? '', /ok/)
})

test('H2 end-to-end: a symlinked .repotector ledger does not exfiltrate into the brief', async () => {
  const outside = await mkdtemp(join(tmpdir(), 'vr-secret2-'))
  await writeFile(join(outside, 'secret.txt'), 'AKIA-LEAKED-EXFIL-VALUE')
  const dir = await mkRepo({ 'package.json': { name: 'evil', version: '1.0.0' } })
  await mkdir(join(dir, '.repotector'), { recursive: true })
  try {
    await symlink(join(outside, 'secret.txt'), join(dir, '.repotector', 'register.jsonl'))
  } catch {
    return // no symlink privilege — skip
  }
  const b = await scout(dir)
  const json = JSON.stringify(b)
  assert.doesNotMatch(json, /AKIA-LEAKED-EXFIL-VALUE/, 'host file content must never reach the brief')
})
