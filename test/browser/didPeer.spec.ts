import { test, expect } from '@playwright/test'

test('did:peer codec passes the test vectors in the browser', async ({
  page
}) => {
  await page.goto('/test/index.html')
  const result = await page.evaluate(async () => {
    // @ts-expect-error -- dev-server URL, resolved at runtime by vite
    const codec = await import('/src/codec.ts')
    const vectors = await (
      await fetch('/test/fixtures/test-vectors.json')
    ).json()
    const failures: string[] = []
    for (const vector of vectors) {
      if (
        codec.encodeLongForm({ inputDocument: vector.inputDocument }) !==
        vector.longForm
      ) {
        failures.push(`${vector.name}: long form`)
      }
      if (
        codec.encodeShortForm({ inputDocument: vector.inputDocument }) !==
        vector.shortForm
      ) {
        failures.push(`${vector.name}: short form`)
      }
      const decoded = codec.decode({ did: vector.longForm })
      if (JSON.stringify(decoded) !== JSON.stringify(vector.inputDocument)) {
        failures.push(`${vector.name}: decode`)
      }
      const resolved = codec.resolveLongForm({ did: vector.longForm })
      if (
        resolved.id !== vector.longForm ||
        resolved.alsoKnownAs.at(-1) !== vector.shortForm
      ) {
        failures.push(`${vector.name}: resolve`)
      }
    }
    return { count: vectors.length, failures }
  })
  expect(result.count).toBe(12)
  expect(result.failures).toEqual([])
})

test('driver generates, resolves and dereferences in the browser', async ({
  page
}) => {
  await page.goto('/test/index.html')
  const result = await page.evaluate(async () => {
    // @ts-expect-error -- dev-server URL, resolved at runtime by vite
    const { run } = await import('/test/browser/harness.ts')
    return run()
  })
  expect(result.did).toMatch(/^did:peer:4zQm/)
  expect(result.keyAgreementCount).toBe(1)
  expect(result.nodeId.startsWith(result.did + '#')).toBe(true)
  expect(result.shortId).toBe(result.did.slice(0, result.did.lastIndexOf(':')))
  expect(result.error).toBeUndefined()
  expect(result.verified).toBe(true)
})
