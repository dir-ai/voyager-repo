#!/usr/bin/env node
/**
 * voyager-repo / voyager-repo MCP server (stdio). One tool: scout_repo — an agent's
 * safe orientation in an unknown repository. Read-only by default; invasive
 * capabilities are explicit booleans that default OFF (fail-closed).
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { resolve } from 'node:path'
import { scout } from './scout.js'
import type { ScoutOptions } from './types.js'
import { VERSION } from './version.js'

const server = new Server({ name: 'voyager-repo', version: VERSION }, { capabilities: { tools: {} } })

const TOOLS = [
  {
    name: 'scout_repo',
    description:
      "Orient in an unknown repository BEFORE touching it — the agent's safe scout. READ-ONLY: maps purpose/structure/build/health, frames every owner-controlled string as untrusted evidence, vets up to `checkDeps` dependencies via Voyager, handshakes with Repotector when present, and WITHHOLDS install/exec/clone (fail-closed). isError:true means orientation could not be produced (tool error), not that the repo is unsafe. Returns an orientation brief + an ordered approach plan.",
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: { type: 'string', maxLength: 4096, description: 'Local repo path (default: cwd). Remote URLs need allowClone.' },
        checkDeps: { type: 'integer', minimum: 0, maximum: 20, description: 'Verify up to N direct dependencies via Voyager (0 = skip).' },
        allowInstall: { type: 'boolean', description: 'Consent to dependency install (still never runs code on the host).' },
        allowExec: { type: 'boolean', description: 'Consent to execution — only ever in a sandbox.' },
        allowClone: { type: 'boolean', description: 'Consent to cloning a remote git URL.' },
        maxFiles: { type: 'integer', minimum: 50, maximum: 20000 },
      },
      required: [],
    },
  },
] as const

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }))

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params
  const a = args as Record<string, unknown>
  const ok = (data: unknown, isError = false) => ({ content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }], ...(isError ? { isError: true } : {}) })
  const err = (message: string) => ok({ error: message }, true)

  try {
    if (name === 'scout_repo') {
      const path = typeof a.path === 'string' && a.path.length > 0 ? resolve(a.path.slice(0, 4096)) : '.'
      const checkDeps = typeof a.checkDeps === 'number' && Number.isInteger(a.checkDeps) ? Math.min(Math.max(a.checkDeps, 0), 20) : 0
      const maxFiles = typeof a.maxFiles === 'number' && Number.isInteger(a.maxFiles) ? Math.min(Math.max(a.maxFiles, 50), 20000) : undefined
      const opts: ScoutOptions = { checkDeps, install: a.allowInstall === true, exec: a.allowExec === true, clone: a.allowClone === true, maxFiles }
      const brief = await scout(path, opts)
      return ok(brief, Boolean(brief.error))
    }
    return err(`Unknown tool: ${name}`)
  } catch (e) {
    return err(e instanceof Error ? e.message : String(e))
  }
})

export async function startMcpServer(): Promise<void> {
  const transport = new StdioServerTransport()
  await server.connect(transport)
  console.error(`voyager-repo (voyager-repo) MCP server v${VERSION} ready (stdio)`)
}

import { fileURLToPath } from 'node:url'
import { realpathSync } from 'node:fs'
function isDirectEntry(): boolean {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const self = fileURLToPath(import.meta.url)
  try {
    return realpathSync(self) === realpathSync(argv1)
  } catch {
    return self === argv1
  }
}
if (isDirectEntry()) {
  startMcpServer().catch((e) => {
    console.error(e instanceof Error ? e.stack : String(e))
    process.exit(1)
  })
}
