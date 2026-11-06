/**
 * Import-graph checks over a fresh compile of `src/`: the only key suite
 * loaded by the driver is `X25519KeyAgreementKey2020` (for key agreement
 * derivation), and the `./codec` entry reaches no driver module and no key
 * suite. The sources are compiled into a temporary directory on every run so
 * a stale `dist/` is never what gets audited.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { execSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const root = path.resolve(import.meta.dirname, '../..')
const dist = fs.mkdtempSync(path.join(os.tmpdir(), 'did-method-peer-dist-'))

function importsOf(file: string): string[] {
  const source = fs.readFileSync(path.join(dist, file), 'utf8')
  const pattern = /^(?:import|export)\b(?:[^;\n]*?\bfrom\s+)?['"]([^'"]+)['"]/gm
  return [...source.matchAll(pattern)].map(match => match[1]!)
}

/**
 * Walks the local import graph from `entry` and returns the local module
 * files and the external package specifiers reached.
 */
function reachable(entry: string): {
  locals: Set<string>
  externals: Set<string>
} {
  const locals = new Set<string>()
  const externals = new Set<string>()
  const queue = [entry]
  while (queue.length > 0) {
    const file = queue.pop()!
    for (const specifier of importsOf(file)) {
      if (specifier.startsWith('./')) {
        const local = specifier.slice(2)
        if (!locals.has(local)) {
          locals.add(local)
          queue.push(local)
        }
      } else {
        externals.add(specifier)
      }
    }
  }
  return { locals, externals }
}

describe('dist import graph', () => {
  beforeAll(() => {
    execSync(`pnpm exec tsc -p tsconfig.json --outDir "${dist}"`, {
      cwd: root,
      stdio: 'pipe'
    })
  }, 60_000)

  afterAll(() => {
    fs.rmSync(dist, { recursive: true, force: true })
  })

  it('the driver imports exactly one key suite at module load', () => {
    const { externals } = reachable('index.js')
    const suites = [...externals].filter(
      specifier =>
        /key|signature|multikey/i.test(specifier) &&
        specifier.startsWith('@') &&
        !specifier.startsWith('@interop/did-io') &&
        !specifier.startsWith('@interop/data-integrity-core')
    )
    expect(suites).toEqual(['@interop/x25519-key-agreement-key'])
  })

  it('the codec entry reaches no driver module and no key suite', () => {
    const { locals, externals } = reachable('codec.js')
    expect(locals.has('DidPeerDriver.js')).toBe(false)
    expect(locals.has('inputDocument.js')).toBe(false)
    expect([...externals].sort()).toEqual([
      '@interop/data-integrity-core',
      '@interop/did-io',
      '@noble/hashes/sha2.js',
      '@noble/hashes/utils.js',
      '@scure/base'
    ])
  })
})
