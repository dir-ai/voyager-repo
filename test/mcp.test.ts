import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { mkRepo } from './_fixtures.js'

const here = dirname(fileURLToPath(import.meta.url))
const MCP = join(here, '..', 'dist', 'mcp.js')

function mcpSession() {
  const child = spawn(process.execPath, [MCP], { stdio: ['pipe', 'pipe', 'inherit'] })
  let buf = ''
  const pending = new Map<number, (m: any) => void>()
  child.stdout.setEncoding('utf8')
  child.stdout.on('data', (chunk: string) => {
    buf += chunk
    let nl: number
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim()
      buf = buf.slice(nl + 1)
      if (!line) continue
      let msg: any
      try { msg = JSON.parse(line) } catch { continue }
      if (msg.id !== undefined && pending.has(msg.id)) { pending.get(msg.id)!(msg); pending.delete(msg.id) }
    }
  })
  const send = (m: unknown) => child.stdin.write(JSON.stringify(m) + '\n')
  const request = (id: number, method: string, params: unknown) =>
    new Promise<any>((res) => { pending.set(id, res); send({ jsonrpc: '2.0', id, method, params }) })
  const notify = (method: string, params?: unknown) => send({ jsonrpc: '2.0', method, params })
  return { child, request, notify }
}

test('MCP: initialize → scout_repo tool present', async () => {
  const s = mcpSession()
  try {
    const init = await s.request(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } })
    assert.equal(init.result?.serverInfo?.name, 'voyager-repo')
    s.notify('notifications/initialized')
    const list = await s.request(2, 'tools/list', {})
    assert.ok((list.result?.tools ?? []).some((t: any) => t.name === 'scout_repo'))
  } finally {
    s.child.kill()
  }
})

test('MCP: scout_repo orients a fixture and stays read-only', async () => {
  const dir = await mkRepo({ 'package.json': { name: 'demo', description: 'x' }, 'src/index.ts': '1\n' })
  const s = mcpSession()
  try {
    await s.request(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } })
    s.notify('notifications/initialized')
    const res = await s.request(3, 'tools/call', { name: 'scout_repo', arguments: { path: dir } })
    const payload = JSON.parse(res.result.content[0].text)
    assert.equal(payload.manifest.name, 'demo')
    assert.equal(payload.approach.permissions.install, false)
    assert.ok(!res.result.isError)
  } finally {
    s.child.kill()
  }
})

test('MCP: a missing path sets isError (tool failure, not a verdict)', async () => {
  const s = mcpSession()
  try {
    await s.request(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } })
    s.notify('notifications/initialized')
    const res = await s.request(4, 'tools/call', { name: 'scout_repo', arguments: { path: '/nope/nope/xyz123' } })
    assert.equal(res.result.isError, true)
  } finally {
    s.child.kill()
  }
})
