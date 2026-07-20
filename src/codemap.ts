import { join } from 'node:path'
import { readTextCapped } from './util.js'
import { cleanInline } from './manifest.js'
import type { CodeComponent, CodeMap, CodeRoute, CodeService, ManifestFacts, StructureMap } from './types.js'

/**
 * The code-intelligence layer: deep, framework-aware, front+back comprehension of a
 * repo WITHOUT executing it. Detects the stack, then extracts the API/route surface,
 * the UI components/pages/views, the config surface (env vars, ports, config files)
 * and the composed services. Regex-and-convention based (zero heavy deps), bounded,
 * and honest about coverage. This is the "what does this system actually DO" map.
 */
export async function buildCodeMap(root: string, files: string[], manifest: ManifestFacts | null, structure: StructureMap | null): Promise<CodeMap> {
  const deps = new Set((manifest?.directDependencies ?? []).map((d) => d.toLowerCase()))
  const has = (name: string): boolean => deps.has(name) || [...deps].some((d) => d === name || d.startsWith(name + '/') || d.startsWith('@' + name))
  const fileSet = new Set(files)
  const stack = detectStack(has, fileSet)

  const routes: CodeRoute[] = []
  const components: CodeComponent[] = []
  const envVars = new Set<string>()
  const ports = new Set<number>()
  const services: CodeService[] = []

  // Which source files to read (bounded): code files, plus compose/Dockerfile.
  const codeFiles = files.filter((f) => /\.(js|mjs|cjs|jsx|ts|tsx|vue|svelte|py|rb|go|java|kt|php)$/i.test(f) && !/\.(min|bundle|d)\.|node_modules\//i.test(f))
  const scanList = codeFiles.slice(0, 400)
  let scanned = 0
  for (const rel of scanList) {
    if (scanned >= 300) break
    const content = await readTextCapped(join(root, rel), 256 * 1024)
    if (content == null) continue
    scanned++
    extractRoutes(rel, content, routes)
    extractComponent(rel, content, components)
    for (const v of content.matchAll(/process\.env\.([A-Z0-9_]{2,64})|import\.meta\.env\.([A-Z0-9_]{2,64})|os\.environ(?:\.get)?\(?\s*["']([A-Z0-9_]{2,64})["']|os\.getenv\(\s*["']([A-Z0-9_]{2,64})["']|ENV\[["']([A-Z0-9_]{2,64})["']\]/g)) {
      const name = v[1] ?? v[2] ?? v[3] ?? v[4] ?? v[5]
      if (name) envVars.add(name)
    }
    for (const p of content.matchAll(/\.listen\(\s*(?:process\.env\.\w+\s*(?:\|\||\?\?)\s*)?(\d{2,5})|PORT[\s:=|?]+(\d{2,5})/g)) {
      const n = Number(p[1] ?? p[2]); if (n >= 1 && n <= 65535) ports.add(n)
    }
  }

  // Convention-based routes/pages the regex pass can't see from content alone
  // (Next.js / SvelteKit / Nuxt file-system routing).
  fileConventionRoutes(files, routes, components, stack)

  // docker-compose services + Dockerfile EXPOSE.
  for (const rel of files) {
    if (/(^|\/)docker-compose(\.\w+)?\.ya?ml$/i.test(rel) || /(^|\/)compose\.ya?ml$/i.test(rel)) {
      const content = await readTextCapped(join(root, rel), 128 * 1024)
      if (content) parseCompose(content, services, ports)
    }
    if (/(^|\/)Dockerfile(\.\w+)?$/i.test(rel)) {
      const content = await readTextCapped(join(root, rel), 64 * 1024)
      if (content) for (const m of content.matchAll(/^\s*EXPOSE\s+(\d{2,5})/gim)) { const n = Number(m[1]); if (n <= 65535) ports.add(n) }
    }
  }

  const configFiles = files.filter((f) => /(^|\/)(\.env[\w.]*|.*\.config\.(js|ts|mjs|cjs)|tsconfig(\.\w+)?\.json|next\.config\.\w+|nuxt\.config\.\w+|vite\.config\.\w+|svelte\.config\.\w+|tailwind\.config\.\w+|nest-cli\.json|angular\.json|vercel\.json|netlify\.toml|serverless\.ya?ml|pyproject\.toml|requirements\.txt|Gemfile|application\.(properties|ya?ml))$/i.test(f)).slice(0, 40)

  const entrypoints = [...new Set([...(structure?.entrypoints ?? []), ...(manifest?.entryHints ?? [])])].slice(0, 12)

  return {
    stack,
    routes: dedupeRoutes(routes).slice(0, 200),
    components: dedupeBy(components, (c) => `${c.name}|${c.file}`).slice(0, 200),
    services,
    config: { envVars: [...envVars].sort().slice(0, 120), configFiles: configFiles.map((f) => cleanInline(f, 120)), ports: [...ports].sort((a, b) => a - b) },
    entrypoints,
    coverage: `scanned ${scanned}/${codeFiles.length} source file(s)${scanned < codeFiles.length ? ' (bounded — larger repos are sampled)' : ''}`,
  }
}

function detectStack(has: (n: string) => boolean, files: Set<string>): string[] {
  const s = new Set<string>()
  const map: Array<[string, () => boolean]> = [
    ['Express', () => has('express')], ['Fastify', () => has('fastify')], ['Koa', () => has('koa')], ['NestJS', () => has('nestjs')],
    ['Next.js', () => has('next') || hasFile(files, /(^|\/)next\.config\./)], ['Nuxt', () => has('nuxt') || hasFile(files, /(^|\/)nuxt\.config\./)],
    ['SvelteKit', () => has('@sveltejs/kit') || hasFile(files, /(^|\/)svelte\.config\./)], ['Remix', () => has('@remix-run/node')], ['Astro', () => has('astro')],
    ['React', () => has('react')], ['Vue', () => has('vue')], ['Svelte', () => has('svelte')], ['Angular', () => has('@angular/core') || files.has('angular.json')],
    ['Flask', () => hasFile(files, /(^|\/)app\.py$/) || files.has('requirements.txt')], ['FastAPI', () => hasFile(files, /(^|\/)main\.py$/)],
    ['Django', () => hasFile(files, /(^|\/)manage\.py$/)], ['Rails', () => files.has('Gemfile') || hasFile(files, /(^|\/)config\/routes\.rb$/)],
    ['Spring', () => files.has('pom.xml') || hasFile(files, /build\.gradle/)], ['Go', () => files.has('go.mod')], ['Docker Compose', () => hasFile(files, /docker-compose|(^|\/)compose\.ya?ml$/)],
  ]
  for (const [name, test] of map) if (test()) s.add(name)
  return [...s]
}
function hasFile(files: Set<string>, re: RegExp): boolean {
  for (const f of files) if (re.test(f)) return true
  return false
}

/** Content-based route extraction across the major JS/TS + Python + Ruby frameworks. */
function extractRoutes(file: string, content: string, out: CodeRoute[]): void {
  const push = (method: string, path: string, kind: CodeRoute['kind'], framework: string): void => {
    if (path && path.length < 200) out.push({ method: method.toUpperCase(), path: cleanInline(path, 160), file: cleanInline(file, 140), kind, framework })
  }
  // Express / Fastify / Koa-router / Hapi: app.get('/x'), router.post("/y"), .route('/z')
  for (const m of content.matchAll(/\b(?:app|router|api|server|route[rs]?|fastify)\s*\.\s*(get|post|put|patch|delete|options|head|all)\s*\(\s*[`'"]([^`'"]+)[`'"]/gi)) push(m[1], m[2], 'api', 'express-like')
  for (const m of content.matchAll(/\.route\s*\(\s*[`'"]([^`'"]+)[`'"]\s*\)/gi)) push('ANY', m[1], 'api', 'express-like')
  // NestJS decorators: @Controller('base') + @Get('sub')
  const controller = /@Controller\s*\(\s*[`'"]([^`'"]*)[`'"]?\s*\)/i.exec(content)?.[1] ?? ''
  for (const m of content.matchAll(/@(Get|Post|Put|Patch|Delete|Options|All)\s*\(\s*[`'"]?([^`'")]*)[`'"]?\s*\)/g)) push(m[1], '/' + [controller, m[2]].filter(Boolean).join('/').replace(/\/+/g, '/'), 'api', 'nestjs')
  // Flask / FastAPI / Django REST: @app.route('/x'), @router.get('/y'), @bp.post
  for (const m of content.matchAll(/@\w+\.(get|post|put|patch|delete)\s*\(\s*[`'"]([^`'"]+)[`'"]/gi)) push(m[1], m[2], 'api', 'python')
  for (const m of content.matchAll(/@\w+\.route\s*\(\s*[`'"]([^`'"]+)[`'"](?:[^)]*methods\s*=\s*\[([^\]]*)\])?/gi)) {
    const methods = m[2] ? m[2].match(/["'](\w+)["']/g)?.map((s) => s.replace(/["']/g, '')) ?? ['GET'] : ['GET']
    for (const meth of methods) push(meth, m[1], 'api', 'flask')
  }
  // Django urls.py: path('x/', view) / re_path
  for (const m of content.matchAll(/\b(?:re_)?path\s*\(\s*[`'"r]?[`'"]([^`'"]*)[`'"]/gi)) push('ANY', '/' + m[1], 'api', 'django')
  // Rails routes.rb: get '/x', resources :y
  for (const m of content.matchAll(/\b(get|post|put|patch|delete)\s+[`'"]([^`'"]+)[`'"]/gi)) if (/routes\.rb$/.test(file)) push(m[1], m[2], 'api', 'rails')
  for (const m of content.matchAll(/\bresources?\s+:(\w+)/gi)) if (/routes\.rb$/.test(file)) push('RESOURCE', '/' + m[1], 'api', 'rails')
  // WebSocket
  for (const m of content.matchAll(/\bnew\s+WebSocketServer\b|io\.on\s*\(\s*[`'"]connection|\.ws\s*\(\s*[`'"]([^`'"]+)[`'"]/gi)) push('WS', m[1] ?? '(socket)', 'websocket', 'websocket')
}

/** Filesystem-routing frameworks: the FILE is the route (Next/Nuxt/SvelteKit/Remix). */
function fileConventionRoutes(files: string[], routes: CodeRoute[], components: CodeComponent[], stack: string[]): void {
  for (const f of files) {
    // Next.js API routes: pages/api/**  OR  app/**/route.{ts,js}
    let m = /(?:^|\/)pages\/api\/(.+)\.(?:js|ts)x?$/i.exec(f)
    if (m) { routes.push({ method: 'ANY', path: '/api/' + m[1].replace(/index$/, ''), file: f, kind: 'api', framework: 'next.js' }); continue }
    m = /(?:^|\/)app\/(.+)\/route\.(?:js|ts)x?$/i.exec(f)
    if (m) { routes.push({ method: 'ANY', path: '/' + m[1], file: f, kind: 'api', framework: 'next.js' }); continue }
    // SvelteKit: +server.ts (API), +page.svelte (page)
    m = /(?:^|\/)src\/routes\/(.*)\+server\.(?:js|ts)$/i.exec(f)
    if (m) { routes.push({ method: 'ANY', path: '/' + m[1].replace(/\/$/, ''), file: f, kind: 'api', framework: 'sveltekit' }); continue }
    m = /(?:^|\/)src\/routes\/(.*)\+page\.svelte$/i.exec(f)
    if (m) { routes.push({ method: 'PAGE', path: '/' + m[1].replace(/\/$/, ''), file: f, kind: 'page', framework: 'sveltekit' }); continue }
    // Next.js pages / app pages
    m = /(?:^|\/)pages\/((?!api\/).+)\.(?:js|ts)x?$/i.exec(f)
    if (m && !/_app|_document/.test(m[1])) { routes.push({ method: 'PAGE', path: '/' + m[1].replace(/index$/, ''), file: f, kind: 'page', framework: 'next.js' }); continue }
    m = /(?:^|\/)app\/(.+)\/page\.(?:js|ts)x?$/i.exec(f)
    if (m) { routes.push({ method: 'PAGE', path: '/' + m[1], file: f, kind: 'page', framework: 'next.js' }); continue }
    // Nuxt pages
    m = /(?:^|\/)pages\/(.+)\.vue$/i.exec(f)
    if (m && stack.includes('Nuxt')) routes.push({ method: 'PAGE', path: '/' + m[1].replace(/index$/, ''), file: f, kind: 'page', framework: 'nuxt' })
  }
}

/** UI component / page / view / layout detection by file type + convention. */
function extractComponent(file: string, content: string, out: CodeComponent[]): void {
  const base = file.split('/').pop() ?? file
  const name = base.replace(/\.[^.]+$/, '')
  const dir = file.toLowerCase()
  const kind: CodeComponent['kind'] = /(^|\/)(pages?|views?|routes)\//.test(dir) ? (/(^|\/)views?\//.test(dir) ? 'view' : 'page') : /layout/i.test(base) ? 'layout' : 'component'
  if (/\.vue$/i.test(file)) { out.push({ name, file, kind, framework: 'vue' }); return }
  if (/\.svelte$/i.test(file)) { out.push({ name, file, kind, framework: 'svelte' }); return }
  if (/@Component\s*\(/.test(content)) { out.push({ name, file, kind, framework: 'angular' }); return }
  // React/Preact: a .jsx/.tsx that returns JSX and exports a PascalCase symbol.
  if (/\.[jt]sx$/i.test(file) && /return\s*\(?\s*</.test(content) && (/export\s+default/.test(content) || /export\s+(?:const|function)\s+[A-Z]/.test(content))) {
    if (/^[A-Z]/.test(name) || kind !== 'component') out.push({ name, file, kind, framework: 'react' })
  }
}

function parseCompose(yaml: string, services: CodeService[], ports: Set<number>): void {
  // Light structural parse (no YAML dep): find `services:` then top-level keys under it.
  const lines = yaml.split(/\r?\n/)
  let inServices = false
  let svcIndent = -1
  let cur: CodeService | null = null
  const flush = (): void => { if (cur) { services.push(cur); cur = null } }
  for (const raw of lines) {
    if (/^\s*#/.test(raw) || !raw.trim()) continue
    const indent = raw.length - raw.trimStart().length
    if (/^services\s*:/.test(raw)) { inServices = true; svcIndent = indent; continue }
    if (!inServices) continue
    if (indent <= svcIndent && !/^\s/.test(raw)) { flush(); inServices = false; continue }
    const svc = /^(\s+)([A-Za-z0-9._-]+)\s*:\s*$/.exec(raw)
    if (svc && svc[1].length === svcIndent + 2) { flush(); cur = { name: svc[2], image: null, ports: [], dependsOn: [] }; continue }
    if (!cur) continue
    const img = /^\s+image\s*:\s*["']?([^"'\n]+)["']?/.exec(raw); if (img) cur.image = cleanInline(img[1].trim(), 120)
    const port = /^\s*-\s*["']?(\d{1,5})(?::(\d{1,5}))?["']?/.exec(raw)
    if (port) { cur.ports.push(cleanInline(raw.trim().replace(/^-\s*/, ''), 40)); const host = Number(port[1]); if (host <= 65535) ports.add(host) }
    const dep = /^\s*-\s*([A-Za-z0-9._-]+)\s*$/.exec(raw); if (dep && /depends_on/i.test(lines[Math.max(0, lines.indexOf(raw) - 1)] ?? '')) cur.dependsOn.push(dep[1])
  }
  flush()
}

function dedupeRoutes(rs: CodeRoute[]): CodeRoute[] {
  return dedupeBy(rs, (r) => `${r.method} ${r.path}`)
}
function dedupeBy<T>(xs: T[], key: (x: T) => string): T[] {
  const seen = new Set<string>()
  return xs.filter((x) => (seen.has(key(x)) ? false : (seen.add(key(x)), true)))
}
