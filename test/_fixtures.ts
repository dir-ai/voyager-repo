import { mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'

/** Write a throwaway repo. Values may be objects (JSON) or raw strings; keys are
 *  repo-relative paths (nested dirs created). */
export async function mkRepo(files: Record<string, unknown>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'pathfinder-'))
  for (const [rel, value] of Object.entries(files)) {
    const path = join(dir, rel)
    await mkdir(dirname(path), { recursive: true })
    await writeFile(path, typeof value === 'string' ? value : JSON.stringify(value, null, 2))
  }
  return dir
}
