import type { BuildInfo, ManifestFacts } from './types.js'

/** Infer the commands an agent COULD run (Voyager Repo never runs them itself). */
export function inferBuild(manifest: ManifestFacts | null): BuildInfo {
  if (!manifest) return { install: null, build: null, test: null, run: null, packageManager: null }

  if (manifest.ecosystem === 'npm') {
    const s = manifest.scripts
    const pm = manifest.hasLockfile ? 'npm' : 'npm'
    const has = (k: string) => (s[k] ? `npm run ${k}` : null)
    return {
      install: 'npm install',
      build: has('build'),
      test: s.test ? 'npm test' : null,
      run: has('start') ?? has('dev'),
      packageManager: pm,
    }
  }
  if (manifest.ecosystem === 'pypi') {
    return { install: 'pip install -e . (or poetry install)', build: null, test: 'pytest', run: null, packageManager: 'pip/poetry' }
  }
  if (manifest.ecosystem === 'cargo') {
    return { install: 'cargo build', build: 'cargo build --release', test: 'cargo test', run: 'cargo run', packageManager: 'cargo' }
  }
  if (manifest.ecosystem === 'go') {
    return { install: 'go mod download', build: 'go build ./...', test: 'go test ./...', run: 'go run .', packageManager: 'go' }
  }
  return { install: null, build: null, test: null, run: null, packageManager: null }
}
