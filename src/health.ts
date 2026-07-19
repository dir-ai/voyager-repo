import { run } from './util.js'
import type { RepoHealth } from './types.js'

/** Derive maintenance/attention signals from git history (read-only). */
export async function scanHealth(root: string): Promise<RepoHealth> {
  const empty: RepoHealth = {
    isGitRepo: false, commits: null, contributors: null, topAuthorShare: null,
    lastCommitISO: null, hotspots: [], archivedHint: false,
  }

  const inside = await run('git', ['rev-parse', '--is-inside-work-tree'], root)
  if (inside.code !== 0 || inside.stdout.trim() !== 'true') return empty

  const [countR, lastR, authorsR, namesR] = await Promise.all([
    run('git', ['rev-list', '--count', 'HEAD'], root),
    run('git', ['log', '-1', '--format=%cI'], root),
    run('git', ['shortlog', '-sn', '--all', '--no-merges'], root, 20_000),
    run('git', ['log', '--name-only', '--format=', '-n', '2000'], root, 20_000),
  ])

  const commits = /^\d+$/.test(countR.stdout.trim()) ? Number(countR.stdout.trim()) : null

  // Contributor concentration (bus factor): `shortlog -sn` = "<count>\t<author>".
  const authorCounts = authorsR.stdout
    .split('\n')
    .map((l) => Number((/^\s*(\d+)\s+/.exec(l)?.[1]) ?? 0))
    .filter((n) => n > 0)
  const contributors = authorCounts.length || null
  const totalByAuthors = authorCounts.reduce((a, b) => a + b, 0)
  const topAuthorShare = totalByAuthors > 0 ? Math.round((authorCounts[0] / totalByAuthors) * 100) / 100 : null

  // Churn hotspots: most-touched files across recent history.
  const churn: Record<string, number> = {}
  for (const line of namesR.stdout.split('\n')) {
    const f = line.trim()
    if (f) churn[f] = (churn[f] ?? 0) + 1
  }
  const hotspots = Object.entries(churn)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([f, n]) => `${f} (${n}×)`)

  return {
    isGitRepo: true,
    commits,
    contributors,
    topAuthorShare,
    lastCommitISO: lastR.code === 0 ? lastR.stdout.trim() || null : null,
    hotspots,
    archivedHint: false,
  }
}
