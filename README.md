# voyager-repo · Pathfinder

**Voyager's repo-penetration organ — the eyes an AI agent sends ahead before it
touches an unknown repository.**

Voyager penetrates the **web** ([`@dir-ai/voyager`](https://www.npmjs.com/package/@dir-ai/voyager)),
the **repo** (this), and — next — **networks**. Repotector is the repo's guardian
that *receives and controls*; Pathfinder is the agent's counterpart that *reaches
outward* and reports back, safely.

```bash
npx @dir-ai/voyager-repo scout .          # orient in the repo you're standing in
npx @dir-ai/voyager-repo scout . --check-deps 10   # + vet 10 deps via Voyager
```

## What it does

Like how Claude or Codex orient themselves in a new codebase — but as a safe,
repeatable tool. `scout` produces an **orientation brief**:

- **purpose** — inferred from the manifest/README, **framed as untrusted** (owner
  text is injection-stripped before it reaches your model)
- **structure** — languages, key dirs (with role guesses), entrypoints
- **build** — the install/build/test/run commands (detected, never run)
- **health** — git signals: commit count, **bus factor** (top-author share),
  recency, churn hotspots
- **dependencies** — composes with **Voyager** to give each dependency a real
  OSV-gated verdict (`--check-deps N`)
- **risks** — install hooks (RCE on `npm install`), committed secrets, missing
  lockfile, large opaque binaries
- **approach plan** — see below

## The approach protocol (the point)

A careful newcomer, not a bulldozer:

1. **Handshake with Repotector** if the repo carries one (`.repotector/`) — read
   its active zones/leases and respect them before editing.
2. **Fail-closed permissions.** Everything is **read-only** by default. Installing
   dependencies, executing code, or cloning a remote is **withheld** until you
   consent (`--allow-install` / `--allow-exec` / `--allow-clone`) — and execution,
   when allowed, belongs in a sandbox.
3. **An orderly tour** — the brief ends with the ordered next steps a well-behaved
   agent should take, so it explores on purpose instead of poking at random.

## Guarantees

- **Nothing in the target is executed on the host.** `scout` reads files and git;
  it never runs the repo's code. (Execution, when consented, runs in Voyager's
  hardened container.)
- **Every owner-controlled byte is untrusted** — README, description, commit
  messages, the Repotector ledger — injection-stripped and framed before your
  model sees it.
- **Exit codes:** `0` oriented · `1` oriented + HIGH-risk finding(s) · `2` tool error.

## MCP

```bash
pathfinder mcp    # or: voyager-repo mcp
```

Tool: `scout_repo` — same orientation, safe-by-default (invasive flags off).

## Library

```ts
import { scout } from '@dir-ai/voyager-repo'
const brief = await scout('/path/to/repo', { checkDeps: 10 })
if (brief.risks.some((r) => r.level === 'high')) { /* caution */ }
```

## Status

`0.x` — Phase 1 (repo orientation) of the Voyager "senses" line. Roadmap:
capability analysis of a package's tarball, PyPI/cargo/go dependency vetting,
and the `net` organ (cloud/infra introspection).

## License

MIT
