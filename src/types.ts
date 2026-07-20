// voyager-repo — the shared shapes for an agent's orientation in an
// unknown repository. Everything the agent reads FROM the repo is untrusted; the
// brief separates verified structural facts from framed, owner-controlled text.

export type Confidence = 'strong' | 'moderate' | 'weak'

/** Text that came from the target (README, manifest description, commit msgs).
 *  `framed` has been injection-stripped; the agent must treat it as DATA. */
export interface FramedText {
  framed: string
  /** How many injection-shaped payloads were stripped out of the raw text. */
  stripped: number
  source: string
}

export interface StructureMap {
  root: string
  fileCount: number
  /** Truncated? (walk is bounded so a huge monorepo can't stall the scout). */
  truncated: boolean
  /** language → file count, most-used first. */
  languages: Record<string, number>
  /** Notable top-level directories (src, test, docs, …) with a role guess. */
  keyDirs: Array<{ path: string; role: string }>
  /** Best-guess entrypoints (from the manifest, then conventional names). */
  entrypoints: string[]
}

export interface ManifestFacts {
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go' | 'unknown'
  name: string | null
  version: string | null
  /** Owner-authored description — FRAMED (untrusted). */
  description: FramedText | null
  /** Declared scripts (npm) — a strong signal of build/test/run + risk (install hooks). */
  scripts: Record<string, string>
  directDependencies: string[]
  hasLockfile: boolean
  /** The package manager implied by the lockfile present (npm/pnpm/yarn), if any. */
  packageManager: 'npm' | 'pnpm' | 'yarn' | 'pip' | 'poetry' | 'cargo' | 'go' | null
  /** Authoritative entrypoints declared by the manifest (main / bin), cleaned. */
  entryHints: string[]
}

export interface BuildInfo {
  /** Detected commands the agent could run (NOT run by Voyager Repo). */
  install: string | null
  build: string | null
  test: string | null
  run: string | null
  packageManager: string | null
}

export interface DependencyFinding {
  name: string
  /** Voyager's verdict, when a check was requested/allowed. */
  verdict?: 'fact' | 'belief' | 'rejected' | 'unknown'
  note?: string
}

export interface DependencyPosture {
  direct: number
  /** How many were actually verified via Voyager (bounded/opt-in). */
  checked: number
  coverage: 'none' | 'sampled' | 'direct' | 'tree'
  findings: DependencyFinding[]
}

export interface RepoHealth {
  isGitRepo: boolean
  commits: number | null
  contributors: number | null
  /** Share of commits by the top author (bus-factor signal), 0..1. */
  topAuthorShare: number | null
  lastCommitISO: string | null
  /** Files with the most changes — likely complexity/attention hotspots. */
  hotspots: string[]
  archivedHint: boolean
}

export type RiskLevel = 'info' | 'low' | 'medium' | 'high'

export interface RiskFinding {
  level: RiskLevel
  kind: string
  detail: string
  /** repo-relative path this finding is anchored to, if any. */
  path?: string
}

/** Whether an invasive capability is permitted this run (fail-closed default). */
export interface Permissions {
  /** Read files/git only — always true; the safe floor. */
  read: true
  /** Run the package manager's install (network + unpack). Off by default. */
  install: boolean
  /** Execute repo code (build/test/run) — only ever in a container. Off by default. */
  exec: boolean
  /** Clone a remote git URL. Off by default. */
  clone: boolean
}

export interface ApproachPlan {
  /** Does the repo carry a Repotector presence to handshake with? */
  repotector: 'present' | 'absent'
  /** What the handshake surfaced (active zones/leases), when present. */
  handshake?: { note: string; framed?: FramedText }
  permissions: Permissions
  /** Actions the agent WANTED to take that were withheld pending consent. */
  withheld: string[]
  /** The orderly next steps a well-behaved agent should take, in order. */
  orderedNextSteps: string[]
}

export interface OrientationBrief {
  target: { input: string; kind: 'local' | 'git-url'; resolvedPath: string | null }
  /** One-line "what is this and what is it for", derived + framed. */
  summary: string
  purpose: FramedText | null
  manifest: ManifestFacts | null
  structure: StructureMap | null
  build: BuildInfo
  dependencies: DependencyPosture
  health: RepoHealth
  risks: RiskFinding[]
  approach: ApproachPlan
  confidence: Confidence
  /** Total framed fields + how many carried a stripped payload. */
  sanitization: { framedFields: number; strippedPayloads: number }
  /** What to look at next to deepen understanding — the agent's next probe. */
  suggestedNextProbe: string[]
  notes: string[]
  /** Set only when orientation could not be produced (tool error) — exit 2. */
  error?: string
}

export interface ScoutOptions {
  /** Verify up to N direct dependencies via Voyager (0 = skip; default small). */
  checkDeps?: number
  install?: boolean
  exec?: boolean
  clone?: boolean
  /** Max files to walk before truncating (protects against huge monorepos). */
  maxFiles?: number
  onLog?: (line: string) => void
}
