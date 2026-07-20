// Voyager Repo (@dir-ai/voyager-repo) — Voyager's repo-penetration organ. Gives an
// AI agent proactive, SAFE orientation in an unknown repository: it reads (never
// executes), frames every owner-controlled byte as untrusted evidence, composes
// with @dir-ai/voyager to vet dependencies, handshakes with Repotector when
// present, and withholds anything invasive (install/exec/clone) until consented.
//
// Voyager penetrates: the WEB (@dir-ai/voyager), the REPO (this), and — next —
// networks. Repotector is the guardian that receives and controls; these are its
// counterpart, the agent's eyes reaching outward.
export { scout } from './scout.js'
export { wrapScanners, adaptTrivy, adaptSemgrep } from './scanners.js'
export { VERSION } from './version.js'
export type {
  OrientationBrief,
  ScoutOptions,
  Permissions,
  ApproachPlan,
  StructureMap,
  ManifestFacts,
  BuildInfo,
  DependencyPosture,
  DependencyFinding,
  RepoHealth,
  RiskFinding,
  RiskLevel,
  FramedText,
  Confidence,
} from './types.js'
