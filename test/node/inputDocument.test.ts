import { describe, it, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { validateInputDocument } from '../../src/index.js'
import {
  addThirdPartyMethod,
  addVerificationMethod
} from '../../src/inputDocument.js'
import vectors from '../fixtures/test-vectors.json' with { type: 'json' }

const ARRAY_PROPERTIES = [
  'verificationMethod',
  'authentication',
  'assertionMethod',
  'keyAgreement',
  'capabilityDelegation',
  'capabilityInvocation',
  'service'
]

describe('validateInputDocument', () => {
  it('accepts every example document and the hello-world vector', () => {
    for (const { inputDocument } of vectors) {
      expect(() => validateInputDocument({ inputDocument })).not.toThrow()
    }
    expect(() =>
      validateInputDocument({ inputDocument: { hello: 'world' } })
    ).not.toThrow()
  })

  it('rejects non-objects and the empty object', () => {
    for (const bad of [0, {}, null, [], 'x']) {
      expect(() =>
        validateInputDocument({ inputDocument: bad as any })
      ).toThrow(/inputDocument: must be a non-empty object/)
    }
  })

  it('rejects a root id', () => {
    expect(() =>
      validateInputDocument({ inputDocument: { id: 'did:peer:4abc' } })
    ).toThrow(/must not have a root "id"/)
  })

  it('rejects a non-array alsoKnownAs', () => {
    expect(() =>
      validateInputDocument({ inputDocument: { alsoKnownAs: 'did:ex:1' } })
    ).toThrow(/alsoKnownAs: must be an array/)
  })

  describe.each(ARRAY_PROPERTIES)('%s', property => {
    it('must be an array', () => {
      expect(() =>
        validateInputDocument({ inputDocument: { [property]: 'not a list' } })
      ).toThrow(`${property}: must be an array.`)
    })
    it('entries must be objects with a string id', () => {
      expect(() =>
        validateInputDocument({ inputDocument: { [property]: [{}] } })
      ).toThrow(`${property}[0]: resource id must be a string.`)
      expect(() =>
        validateInputDocument({ inputDocument: { [property]: [{ id: 0 }] } })
      ).toThrow(`${property}[0]: resource id must be a string.`)
      expect(() =>
        validateInputDocument({ inputDocument: { [property]: ['#ok', 5] } })
      ).toThrow(`${property}[1]: resource must be an object.`)
    })
    it('entries must have a relative id', () => {
      expect(() =>
        validateInputDocument({
          inputDocument: {
            [property]: ['#ok', { id: 'did:peer:4zQm:abc#key-1', type: 'T' }]
          }
        })
      ).toThrow(`${property}[1]: resource id must be relative.`)
      expect(() =>
        validateInputDocument({
          inputDocument: { [property]: [{ id: '#', type: 'T' }] }
        })
      ).toThrow(/resource id must be relative/)
      expect(() =>
        validateInputDocument({
          inputDocument: { [property]: [{ id: '##x', type: 'T' }] }
        })
      ).toThrow(/resource id must be relative/)
    })
    it('entries must have a type', () => {
      expect(() =>
        validateInputDocument({
          inputDocument: { [property]: [{ id: '#key-1' }] }
        })
      ).toThrow(`${property}[0]: resource must have a type.`)
    })
  })

  it('does not check string references', () => {
    expect(() =>
      validateInputDocument({
        inputDocument: { authentication: ['did:key:z6Mkabc#z6Mkabc'] }
      })
    ).not.toThrow()
  })

  it('rejects duplicate resource ids across arrays', () => {
    expect(() =>
      validateInputDocument({
        inputDocument: {
          verificationMethod: [{ id: '#k', type: 'Multikey' }],
          keyAgreement: [{ id: '#k', type: 'X25519KeyAgreementKey2020' }]
        }
      })
    ).toThrow(
      'keyAgreement[0]: duplicate resource id "#k" (also at verificationMethod[0]).'
    )
    expect(() =>
      validateInputDocument({
        inputDocument: {
          verificationMethod: [{ id: '#k', type: 'Multikey' }],
          service: [{ id: '#k', type: 'DIDCommMessaging' }]
        }
      })
    ).toThrow(/duplicate resource id/)
  })
})

describe('addVerificationMethod', () => {
  it('exports a stripped, relative node and references it', async () => {
    const keyPair = await Ed25519VerificationKey.generate({
      controller: 'did:example:previous'
    })
    expect(keyPair.id).toContain('did:example:previous#')
    const inputDocument: Record<string, unknown> = {
      '@context': ['https://www.w3.org/ns/did/v1']
    }
    const { fragment } = await addVerificationMethod({
      inputDocument,
      keyPair,
      purposes: ['authentication', 'assertionMethod']
    })
    expect(fragment).toBe(keyPair.fingerprint())
    expect(inputDocument['@context']).toEqual([
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/multikey/v1'
    ])
    const [node] = inputDocument.verificationMethod as any[]
    expect(node).toEqual({
      id: `#${fragment}`,
      type: 'Multikey',
      publicKeyMultibase: keyPair.publicKeyMultibase
    })
    expect(node).not.toHaveProperty('controller')
    expect(node).not.toHaveProperty('@context')
    expect(inputDocument.authentication).toEqual([`#${fragment}`])
    expect(inputDocument.assertionMethod).toEqual([`#${fragment}`])
    // the live pair is untouched by the stripping
    expect(keyPair.controller).toBe('did:example:previous')
  })

  it('honors a fragment override and de-duplicates contexts', async () => {
    const keyPair = await Ed25519VerificationKey.generate()
    const inputDocument: Record<string, unknown> = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/multikey/v1'
      ]
    }
    await addVerificationMethod({
      inputDocument,
      keyPair,
      fragment: 'key-1',
      purposes: ['authentication', 'capabilityInvocation']
    })
    expect(inputDocument['@context']).toEqual([
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/multikey/v1'
    ])
    const [node] = inputDocument.verificationMethod as any[]
    expect(node.id).toBe('#key-1')
    expect(inputDocument.authentication).toEqual(['#key-1'])
    expect(inputDocument.capabilityInvocation).toEqual(['#key-1'])
  })

  it('handles a derived X25519 node: own id and the x25519-2020 context', async () => {
    const ed = await Ed25519VerificationKey.generate()
    const x = X25519KeyAgreementKey2020.fromEd25519({
      publicKeyMultibase: ed.publicKeyMultibase,
      privateKeyMultibase: ed.privateKeyMultibase
    })
    expect(x.id).toBeUndefined()
    const inputDocument: Record<string, unknown> = {
      '@context': ['https://www.w3.org/ns/did/v1']
    }
    const { fragment } = await addVerificationMethod({
      inputDocument,
      keyPair: x as any,
      purposes: ['keyAgreement']
    })
    expect(fragment).toBe(x.fingerprint())
    expect(fragment.startsWith('z6LS')).toBe(true)
    expect(inputDocument['@context']).toContain(
      'https://w3id.org/security/suites/x25519-2020/v1'
    )
    const [node] = inputDocument.verificationMethod as any[]
    expect(node.id).toBe(`#${fragment}`)
    expect(node.type).toBe('X25519KeyAgreementKey2020')
    expect(inputDocument.keyAgreement).toEqual([`#${fragment}`])
  })

  it('rejects an unsupported purpose and a non-live key pair', async () => {
    const keyPair = await Ed25519VerificationKey.generate()
    await expect(
      addVerificationMethod({
        inputDocument: {},
        keyPair,
        purposes: ['bogus']
      })
    ).rejects.toThrow(/Unsupported key purpose/)
    await expect(
      addVerificationMethod({
        inputDocument: {},
        keyPair: { publicKeyMultibase: 'z6Mk' } as any
      })
    ).rejects.toThrow(TypeError)
  })
})

describe('addThirdPartyMethod', () => {
  it('appends a string reference to each purpose only', () => {
    const inputDocument: Record<string, unknown> = {}
    addThirdPartyMethod({
      inputDocument,
      entry: 'did:key:z6Mkabc#z6Mkabc',
      purposes: ['authentication']
    })
    expect(inputDocument).toEqual({
      authentication: ['did:key:z6Mkabc#z6Mkabc']
    })
  })

  it('places a method object verbatim and references it', () => {
    const inputDocument: Record<string, unknown> = {}
    const entry = {
      id: '#other',
      type: 'Multikey' as const,
      controller: 'did:key:z6Mkabc',
      publicKeyMultibase: 'z6Mkabc'
    }
    addThirdPartyMethod({ inputDocument, entry, purposes: ['assertionMethod'] })
    expect(inputDocument.verificationMethod).toEqual([entry])
    expect((inputDocument.verificationMethod as any[])[0]).not.toBe(entry)
    expect(inputDocument.assertionMethod).toEqual(['#other'])
  })

  it('rejects an object without a string id', () => {
    expect(() =>
      addThirdPartyMethod({
        inputDocument: {},
        entry: { type: 'Multikey' } as any,
        purposes: ['authentication']
      })
    ).toThrow(TypeError)
  })
})
