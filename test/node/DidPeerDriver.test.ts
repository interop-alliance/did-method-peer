import { describe, it, expect, beforeEach } from 'vitest'
import { base58 } from '@scure/base'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import {
  decode,
  driver,
  DidPeerDriver,
  encodeLongForm,
  isLongForm,
  longToShort,
  resolveLongForm,
  MAX_LONG_FORM_LENGTH
} from '../../src/index.js'
import type { LongFormStore } from '../../src/index.js'
import vectors from '../fixtures/test-vectors.json' with { type: 'json' }
import seedFixture from '../fixtures/seed-generation.json' with { type: 'json' }

const SEED = 'z1AhV1bADy7RepJ64mvH7Kk7htFNGc7EA1WA5nGzLSTWc6o'
const SEED_KEY = 'z6MkmDMjfkjs9XPCN1LfoQQRHz1mJ8PEdiVYC66XKhj3wGyB'

async function rejectsWith(
  promise: Promise<unknown>,
  {
    name,
    code,
    messagePart
  }: { name: string; code?: string; messagePart?: string }
): Promise<Error & { code?: string; cause?: unknown }> {
  let caught: unknown
  try {
    await promise
  } catch (err) {
    caught = err
  }
  expect(caught, 'expected a rejection').toBeInstanceOf(Error)
  const error = caught as Error & { code?: string; cause?: unknown }
  expect(error.name).toBe(name)
  if (code) {
    expect(error.code).toBe(code)
  }
  if (messagePart) {
    expect(error.message).toContain(messagePart)
  }
  return error
}

function makeDriver(
  options: ConstructorParameters<typeof DidPeerDriver>[0] = {}
) {
  const didPeer = driver(options)
  didPeer.use({ keyPairClass: Ed25519VerificationKey })
  return didPeer
}

/**
 * Applies the driver's reference resolution to a codec document, for
 * comparing driver output with codec output.
 */
function absolutize(doc: any, did: string): any {
  const out = structuredClone(doc)
  for (const property of [
    'verificationMethod',
    'authentication',
    'assertionMethod',
    'capabilityDelegation',
    'capabilityInvocation',
    'keyAgreement',
    'service'
  ]) {
    const entries = out[property]
    if (!Array.isArray(entries)) {
      continue
    }
    out[property] = entries.map((entry: any) => {
      if (typeof entry === 'string') {
        return property === 'verificationMethod' || property === 'service'
          ? entry
          : entry.startsWith('#')
            ? `${did}${entry}`
            : entry
      }
      if (typeof entry.id === 'string' && entry.id.startsWith('#')) {
        return { ...entry, id: `${did}${entry.id}` }
      }
      return entry
    })
  }
  return out
}

describe('DidPeerDriver', () => {
  it('has method "peer" and the driver() factory', () => {
    expect(driver().method).toBe('peer')
    expect(driver()).toBeInstanceOf(DidPeerDriver)
    expect(driver().rememberOnResolve).toBe(true)
  })

  describe('use()', () => {
    it('validates the two registration forms', () => {
      const didPeer = driver()
      expect(() => didPeer.use({ keyPairClass: {} as any })).toThrow(TypeError)
      expect(() => didPeer.use({ multibaseMultikeyHeader: 'z6Mk' })).toThrow(
        TypeError
      )
      expect(() => didPeer.use()).toThrow(TypeError)
      didPeer.use({
        multibaseMultikeyHeader: 'z6LS',
        fromMultibase: X25519KeyAgreementKey2020.from.bind(
          X25519KeyAgreementKey2020
        ) as any
      })
      expect(didPeer._allowedKeyTypes.has('z6LS')).toBe(true)
    })
  })

  describe('generate() with no arguments', () => {
    it('produces one Multikey method with four purposes and bound live pairs', async () => {
      const didPeer = makeDriver()
      const { didDocument, keyPairs, methodFor } = await didPeer.generate()
      const doc = didDocument as any
      const longForm = doc.id as string
      expect(isLongForm(longForm)).toBe(true)
      expect(doc.alsoKnownAs).toEqual([longToShort({ did: longForm })])
      expect(doc['@context']).toEqual([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/multikey/v1'
      ])
      expect(doc.verificationMethod).toHaveLength(1)
      const [method] = doc.verificationMethod
      expect(method.type).toBe('Multikey')
      expect(method.id).toBe(`${longForm}#${method.publicKeyMultibase}`)
      expect(method.controller).toBe(longForm)
      for (const purpose of [
        'authentication',
        'assertionMethod',
        'capabilityDelegation',
        'capabilityInvocation'
      ]) {
        expect(doc[purpose]).toEqual([method.id])
      }
      expect(doc.keyAgreement).toBeUndefined()
      expect([...keyPairs.keys()]).toEqual([method.id])
      const pair = methodFor({ purpose: 'authentication' })
      expect(pair.id).toBe(method.id)
      expect(pair.controller).toBe(longForm)
      expect(keyPairs.get(method.id)).toBe(pair)
      expect(() => methodFor({ purpose: 'keyAgreement' })).toThrow(
        /No verification method found/
      )
      // the input document has the relative id
      const inputDocument = decode({ did: longForm }) as any
      expect(inputDocument.verificationMethod[0].id).toBe(
        `#${method.publicKeyMultibase}`
      )
      expect(inputDocument.verificationMethod[0]).not.toHaveProperty(
        'controller'
      )
    })

    it('derives an X25519 key agreement key when enabled', async () => {
      const didPeer = driver()
      didPeer.use({
        keyPairClass: Ed25519VerificationKey,
        enableEncryptionKeyDerivation: true
      })
      const { didDocument, keyPairs, methodFor } = await didPeer.generate()
      const doc = didDocument as any
      expect(doc['@context']).toEqual([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/multikey/v1',
        'https://w3id.org/security/suites/x25519-2020/v1'
      ])
      expect(doc.verificationMethod).toHaveLength(2)
      const kak = doc.verificationMethod[1]
      expect(kak.type).toBe('X25519KeyAgreementKey2020')
      expect(kak.publicKeyMultibase.startsWith('z6LS')).toBe(true)
      expect(kak.id).toBe(`${doc.id}#${kak.publicKeyMultibase}`)
      expect(doc.keyAgreement).toEqual([kak.id])
      expect(keyPairs.size).toBe(2)
      const pair = methodFor({ purpose: 'keyAgreement' }) as any
      expect(pair.id).toBe(kak.id)
      expect(pair.privateKeyMultibase).toBeDefined()
    })

    it('matches the generated document shape of the design', async () => {
      const didPeer = driver()
      didPeer.use({
        keyPairClass: Ed25519VerificationKey,
        enableEncryptionKeyDerivation: true
      })
      const { didDocument } = await didPeer.generate()
      const inputDocument = decode({ did: (didDocument as any).id })
      expect(Object.keys(inputDocument)).toEqual([
        '@context',
        'verificationMethod',
        'authentication',
        'assertionMethod',
        'capabilityDelegation',
        'capabilityInvocation',
        'keyAgreement'
      ])
    })
  })

  describe('generate() option conflicts', () => {
    const didPeer = makeDriver()
    it('rejects invalid combinations with TypeError', async () => {
      const pair = await Ed25519VerificationKey.generate()
      await expect(didPeer.generate({ keyPairs: new Map() })).rejects.toThrow(
        TypeError
      )
      await expect(
        didPeer.generate({ inputDocument: { hello: 'world' }, seed: SEED })
      ).rejects.toThrow(TypeError)
      await expect(
        didPeer.generate({
          inputDocument: { hello: 'world' },
          service: [{ id: '#s', type: 'T' }]
        })
      ).rejects.toThrow(TypeError)
      await expect(
        didPeer.generate({ seed: SEED, verificationKeyPair: pair })
      ).rejects.toThrow(TypeError)
      await expect(
        didPeer.generate({ keyType: 'z6Mk', verificationKeyPair: pair })
      ).rejects.toThrow(TypeError)
      await expect(
        didPeer.generate({ seed: new Uint8Array(16) })
      ).rejects.toThrow(/32 bytes/)
      await expect(didPeer.generate({ seed: 'abc' })).rejects.toThrow(TypeError)
    })
  })

  describe('generate({ seed })', () => {
    it('is deterministic and matches the did-web fixture key', async () => {
      const didPeer = makeDriver()
      const first = await didPeer.generate({ seed: SEED })
      const second = await didPeer.generate({ seed: SEED })
      expect((first.didDocument as any).id).toBe((second.didDocument as any).id)
      const [method] = (first.didDocument as any).verificationMethod
      expect(method.publicKeyMultibase).toBe(SEED_KEY)
      expect(method.id).toBe(`${(first.didDocument as any).id}#${SEED_KEY}`)
      // Pin the generation path, not just the codec.
      expect((first.didDocument as any).id).toBe(seedFixture.longForm)
      expect(decode({ did: seedFixture.longForm })).toEqual(
        seedFixture.inputDocument
      )
    })

    it('accepts a 32-byte Uint8Array seed', async () => {
      const didPeer = makeDriver()
      const seed = new Uint8Array(32).fill(7)
      const first = await didPeer.generate({ seed })
      const second = await didPeer.generate({ seed })
      expect((first.didDocument as any).id).toBe((second.didDocument as any).id)
    })
  })

  describe('generate() path 3 variants', () => {
    it('accepts verificationKeyPair and keyAgreementKeyPair', async () => {
      const didPeer = makeDriver()
      const verificationKeyPair = await Ed25519VerificationKey.generate()
      const keyAgreementKeyPair = await X25519KeyAgreementKey2020.generate()
      const { didDocument, methodFor } = await didPeer.generate({
        verificationKeyPair,
        keyAgreementKeyPair: keyAgreementKeyPair as any
      })
      const doc = didDocument as any
      expect(doc.verificationMethod).toHaveLength(2)
      expect(doc['@context']).toContain(
        'https://w3id.org/security/suites/x25519-2020/v1'
      )
      expect(methodFor({ purpose: 'keyAgreement' })).toBe(keyAgreementKeyPair)
      expect(methodFor({ purpose: 'authentication' })).toBe(verificationKeyPair)
      expect(verificationKeyPair.controller).toBe(doc.id)
    })

    it('honours verificationMethods with fragment and purposes, plus service', async () => {
      const didPeer = makeDriver()
      const a = await Ed25519VerificationKey.generate()
      const b = await Ed25519VerificationKey.generate()
      const service = [
        {
          id: '#didcomm-0',
          type: 'DIDCommMessaging',
          serviceEndpoint: { uri: 'didcomm:transport/queue' }
        }
      ]
      const { didDocument, keyPairs, methodFor } = await didPeer.generate({
        verificationMethods: [
          { keyPair: a, fragment: 'key-1', purposes: ['authentication'] },
          { keyPair: b, purposes: ['assertionMethod'] }
        ],
        service
      })
      const doc = didDocument as any
      expect(doc.verificationMethod.map((m: any) => m.id)).toEqual([
        `${doc.id}#key-1`,
        `${doc.id}#${b.fingerprint()}`
      ])
      expect(doc.authentication).toEqual([`${doc.id}#key-1`])
      expect(doc.assertionMethod).toEqual([`${doc.id}#${b.fingerprint()}`])
      expect(doc.capabilityInvocation).toBeUndefined()
      expect(doc.service).toEqual([
        { ...service[0], id: `${doc.id}#didcomm-0` }
      ])
      // service was copied, not aliased
      expect(service[0]!.id).toBe('#didcomm-0')
      expect(keyPairs.get(`${doc.id}#key-1`)).toBe(a)
      expect(methodFor({ purpose: 'authentication' })).toBe(a)
      expect(a.id).toBe(`${doc.id}#key-1`)
    })

    it('does not add a default key when only verificationMethods are given', async () => {
      const didPeer = driver()
      didPeer.use({
        keyPairClass: Ed25519VerificationKey,
        enableEncryptionKeyDerivation: true
      })
      const a = await Ed25519VerificationKey.generate()
      const { didDocument } = await didPeer.generate({
        verificationMethods: [{ keyPair: a }]
      })
      const doc = didDocument as any
      expect(doc.verificationMethod).toHaveLength(1)
      expect(doc.keyAgreement).toBeUndefined()
      expect(doc.authentication).toEqual([`${doc.id}#${a.fingerprint()}`])
    })

    it('places third-party entries verbatim with the default purposes', async () => {
      const didPeer = makeDriver()
      const reference = `did:key:${SEED_KEY}#${SEED_KEY}`
      const other = await Ed25519VerificationKey.generate()
      const method = {
        id: '#other',
        type: 'Multikey',
        controller: `did:key:${other.fingerprint()}`,
        publicKeyMultibase: other.publicKeyMultibase
      }
      const { didDocument, keyPairs, methodFor } = await didPeer.generate({
        verificationMethods: [reference, method as any]
      })
      const doc = didDocument as any
      expect(doc.verificationMethod).toEqual([
        { ...method, id: `${doc.id}#other` }
      ])
      expect(doc.authentication).toEqual([reference, `${doc.id}#other`])
      expect(doc.capabilityDelegation).toEqual([reference, `${doc.id}#other`])
      expect(keyPairs.size).toBe(0)
      // did-io takes the first entry, a foreign reference it cannot find
      expect(() => methodFor({ purpose: 'authentication' })).toThrow(
        /No verification method found/
      )
    })

    it('narrows a third-party entry to explicit purposes', async () => {
      const didPeer = makeDriver()
      const reference = `did:key:${SEED_KEY}#${SEED_KEY}`
      const other = await Ed25519VerificationKey.generate()
      const method = {
        id: '#other',
        type: 'Multikey',
        controller: `did:key:${other.fingerprint()}`,
        publicKeyMultibase: other.publicKeyMultibase
      }
      const { didDocument } = await didPeer.generate({
        verificationMethods: [
          { method: reference, purposes: ['authentication'] },
          { method: method as any, purposes: ['assertionMethod'] }
        ]
      })
      const doc = didDocument as any
      expect(doc.verificationMethod).toEqual([
        { ...method, id: `${doc.id}#other` }
      ])
      expect(doc.authentication).toEqual([reference])
      expect(doc.assertionMethod).toEqual([`${doc.id}#other`])
      expect(doc.capabilityInvocation).toBeUndefined()
      expect(doc.capabilityDelegation).toBeUndefined()
      await expect(
        didPeer.generate({
          verificationMethods: [{ method: reference, purposes: ['bogus'] }]
        })
      ).rejects.toThrow(/Unsupported key purpose/)
    })

    it('rejects a third-party method object with an absolute id', async () => {
      const didPeer = makeDriver()
      await expect(
        didPeer.generate({
          verificationMethods: [
            {
              id: 'did:key:z6Mkabc#z6Mkabc',
              type: 'Multikey',
              controller: 'did:key:z6Mkabc',
              publicKeyMultibase: 'z6Mkabc'
            } as any
          ]
        })
      ).rejects.toThrow(/resource id must be relative/)
    })

    it('rejects duplicate fragments and bad fragment overrides via validation', async () => {
      const didPeer = makeDriver()
      const a = await Ed25519VerificationKey.generate()
      await expect(
        didPeer.generate({
          verificationKeyPair: a,
          verificationMethods: [{ keyPair: a }]
        })
      ).rejects.toThrow(/duplicate resource id/)
      await expect(
        didPeer.generate({
          verificationMethods: [{ keyPair: a, fragment: '' }]
        })
      ).rejects.toThrow(/resource id must be relative/)
      await expect(
        didPeer.generate({
          verificationMethods: [{ keyPair: a, fragment: '#x' }]
        })
      ).rejects.toThrow(/resource id must be relative/)
    })

    it('suite selection errors use the did-web-resolver messages', async () => {
      const none = driver()
      await expect(none.generate()).rejects.toThrow(
        'No key suite registered; call "use({keyPairClass})" or pass a "verificationKeyPair".'
      )
      const two = makeDriver()
      two.use({
        multibaseMultikeyHeader: 'z6LS',
        fromMultibase: X25519KeyAgreementKey2020.from.bind(
          X25519KeyAgreementKey2020
        ) as any
      })
      await expect(two.generate()).rejects.toThrow(
        'Multiple key suites registered; specify which via "keyType" or pass a "verificationKeyPair".'
      )
      await expect(two.generate({ keyType: 'z6LS' })).rejects.toThrow(
        'Registered suite "z6LS" cannot generate keys; register it via "use({keyPairClass})".'
      )
      const byClass = await two.generate({ keyType: Ed25519VerificationKey })
      expect(isLongForm((byClass.didDocument as any).id)).toBe(true)
    })
  })

  describe('generate({ inputDocument })', () => {
    it('resolves a caller document as given, with reference resolution', async () => {
      const didPeer = makeDriver()
      const vector = vectors.find(v => v.name === 'examples/2.json')!
      const { didDocument, keyPairs, methodFor } = await didPeer.generate({
        inputDocument: vector.inputDocument
      })
      expect((didDocument as any).id).toBe(vector.longForm)
      expect(didDocument).toEqual(
        absolutize(resolveLongForm({ did: vector.longForm }), vector.longForm)
      )
      expect(keyPairs.size).toBe(0)
      expect(() => methodFor({ purpose: 'authentication' })).toThrow(
        /No key pair available/
      )
    })

    it('rejects an invalid input document', async () => {
      const didPeer = makeDriver()
      await expect(
        didPeer.generate({ inputDocument: { id: 'did:x' } })
      ).rejects.toThrow(TypeError)
    })

    it('binds live pairs by fragment, including embedded methods', async () => {
      const didPeer = makeDriver()
      const a = await Ed25519VerificationKey.generate()
      const b = await Ed25519VerificationKey.generate()
      const inputDocument = {
        '@context': ['https://www.w3.org/ns/did/v1'],
        verificationMethod: [
          {
            id: '#a',
            type: 'Multikey',
            publicKeyMultibase: a.publicKeyMultibase
          }
        ],
        authentication: ['#a'],
        assertionMethod: [
          {
            id: '#b',
            type: 'Multikey',
            publicKeyMultibase: b.publicKeyMultibase
          }
        ],
        capabilityInvocation: ['#unbound']
      }
      const { didDocument, keyPairs, methodFor } = await didPeer.generate({
        inputDocument,
        keyPairs: new Map([
          ['a', a],
          ['b', b]
        ])
      })
      const did = (didDocument as any).id
      expect([...keyPairs.keys()]).toEqual([`${did}#a`, `${did}#b`])
      expect(methodFor({ purpose: 'authentication' })).toBe(a)
      expect(methodFor({ purpose: 'assertionMethod' })).toBe(b)
      expect(a.id).toBe(`${did}#a`)
      expect(b.controller).toBe(did)
      expect(() => methodFor({ purpose: 'capabilityInvocation' })).toThrow()
    })

    it('rejects a keyPairs fragment missing from the document or with a different key', async () => {
      const didPeer = makeDriver()
      const a = await Ed25519VerificationKey.generate()
      const b = await Ed25519VerificationKey.generate()
      const inputDocument = {
        verificationMethod: [
          {
            id: '#a',
            type: 'Multikey',
            publicKeyMultibase: a.publicKeyMultibase
          }
        ],
        authentication: ['#a']
      }
      await expect(
        didPeer.generate({ inputDocument, keyPairs: new Map([['zzz', a]]) })
      ).rejects.toThrow(/no method with id "#zzz"/)
      await expect(
        didPeer.generate({ inputDocument, keyPairs: new Map([['a', b]]) })
      ).rejects.toThrow(/does not match the public key/)
    })

    it('binds a pair to a method in another serialization via its suite', async () => {
      const didPeer = makeDriver()
      const a = await Ed25519VerificationKey.generate()
      const b = await Ed25519VerificationKey.generate()
      const inputDocument = {
        verificationMethod: [
          {
            id: '#jwk',
            type: 'JsonWebKey',
            publicKeyJwk: a.toJwk({ publicKey: true })
          },
          {
            id: '#b58',
            type: 'Ed25519VerificationKey2018',
            // raw key bytes: strip the multibase prefix and 2-byte multicodec
            publicKeyBase58: base58.encode(
              base58.decode(b.publicKeyMultibase!.slice(1)).slice(2)
            )
          }
        ],
        authentication: ['#jwk'],
        assertionMethod: ['#b58']
      }
      const { methodFor } = await didPeer.generate({
        inputDocument,
        keyPairs: new Map([
          ['jwk', a],
          ['b58', b]
        ])
      })
      expect(methodFor({ purpose: 'authentication' })).toBe(a)
      expect(methodFor({ purpose: 'assertionMethod' })).toBe(b)
      await expect(
        didPeer.generate({ inputDocument, keyPairs: new Map([['jwk', b]]) })
      ).rejects.toThrow(/does not match the public key/)
      const unreadable = {
        verificationMethod: [{ id: '#x', type: 'Mystery', publicKeyHex: '00' }],
        authentication: ['#x']
      }
      await expect(
        didPeer.generate({
          inputDocument: unreadable,
          keyPairs: new Map([['x', a]])
        })
      ).rejects.toThrow(/does not match the public key/)
    })
  })

  describe('fromKeyPair() and publicKeyToDidDoc()', () => {
    it('fromKeyPair requires a key and accepts plain descriptions', async () => {
      const didPeer = makeDriver()
      await expect(didPeer.fromKeyPair()).rejects.toThrow(TypeError)
      const live = await Ed25519VerificationKey.generate()
      const description = { publicKeyMultibase: live.publicKeyMultibase }
      const { didDocument, keyPairs } = await didPeer.fromKeyPair({
        verificationKeyPair: description as any
      })
      const doc = didDocument as any
      expect(doc.verificationMethod[0].publicKeyMultibase).toBe(
        live.publicKeyMultibase
      )
      const [pair] = keyPairs.values()
      expect(pair).toBeInstanceOf(Ed25519VerificationKey)
      await expect(
        didPeer.fromKeyPair({
          verificationKeyPair: { type: 'Multikey' } as any
        })
      ).rejects.toThrow(/"publicKeyMultibase" is required/)
    })

    it('fromKeyPair with only keyAgreementKeyPair generates no signing key', async () => {
      const didPeer = makeDriver()
      const kak = await X25519KeyAgreementKey2020.generate()
      const { didDocument } = await didPeer.fromKeyPair({
        keyAgreementKeyPair: kak as any
      })
      const doc = didDocument as any
      expect(doc.verificationMethod).toHaveLength(1)
      expect(doc.keyAgreement).toEqual([doc.verificationMethod[0].id])
      expect(doc.authentication).toBeUndefined()
    })

    it('publicKeyToDidDoc classifies X25519 as keyAgreement and does not write the store', async () => {
      const store = new Map<string, string>()
      const didPeer = makeDriver({ longFormStore: store })
      didPeer.use({
        multibaseMultikeyHeader: 'z6LS',
        fromMultibase: X25519KeyAgreementKey2020.from.bind(
          X25519KeyAgreementKey2020
        ) as any
      })
      const kak = await X25519KeyAgreementKey2020.generate()
      const result = await didPeer.publicKeyToDidDoc({
        publicKeyDescription: {
          publicKeyMultibase: kak.publicKeyMultibase
        } as any
      })
      expect(Object.keys(result)).toEqual(['didDocument'])
      const doc = result.didDocument as any
      expect(doc.keyAgreement).toHaveLength(1)
      expect(doc.verificationMethod[0].type).toBe('X25519KeyAgreementKey2020')
      expect(store.size).toBe(0)

      const ed = await Ed25519VerificationKey.generate()
      const { didDocument } = await didPeer.publicKeyToDidDoc({
        publicKeyDescription: ed
      })
      expect((didDocument as any).authentication).toHaveLength(1)
      await expect(didPeer.publicKeyToDidDoc()).rejects.toThrow(TypeError)
    })
  })

  describe('get()', () => {
    const vector = vectors.find(v => v.name === 'examples/0.json')!
    const { longForm, shortForm } = vector

    it('requires a did or url', async () => {
      await expect(driver().get()).rejects.toThrow(TypeError)
    })

    it('resolves a long form to the codec output with absolute references', async () => {
      const didPeer = driver()
      const doc = (await didPeer.get({ did: longForm })) as any
      expect(doc).toEqual(
        absolutize(resolveLongForm({ did: longForm }), longForm)
      )
      expect(doc.verificationMethod[0].id).toBe(`${longForm}#1`)
      expect(doc.authentication).toEqual([`${longForm}#1`])
      expect(doc.service[0].id).toBe(`${longForm}#didcomm`)
      // service contents and absolute references are untouched
      expect(doc.service[0].recipientKeys).toEqual(['#1'])
      expect(doc.service[0].routingKeys).toEqual(
        (vector.inputDocument.service![0] as any).routingKeys
      )
    })

    it('leaves vector 3 publicKey alone and resolves embedded keyAgreement', async () => {
      const v6 = vectors.find(v => v.name === 'examples/3.json')!
      const doc = (await driver().get({ did: v6.longForm })) as any
      expect(doc.publicKey).toEqual(v6.inputDocument.publicKey)
      expect(doc.keyAgreement[0].id).toBe(
        `${v6.longForm}#zC8GybikEfyNaausDA4mkT4egP7SNLx2T1d1kujLQbcP6h`
      )
      expect(doc.authentication[0]).toBe(
        `${v6.longForm}#z6MkrmNwty5ajKtFqc1U48oL2MMLjWjartwc5sf2AihZwXDN`
      )
    })

    it('rejects other methods and numalgos with methodNotSupported', async () => {
      const didPeer = driver()
      await rejectsWith(didPeer.get({ did: 'did:key:z6Mkabc' }), {
        name: 'DIDResolutionError',
        code: 'methodNotSupported'
      })
      await rejectsWith(didPeer.get({ did: 'did:peer:2.Ez6LSabc' }), {
        name: 'DIDResolutionError',
        code: 'methodNotSupported',
        messagePart: 'numalgo 2'
      })
      await rejectsWith(didPeer.get({ did: 'did:peer:0z6Mkabc' }), {
        name: 'DIDResolutionError',
        code: 'methodNotSupported',
        messagePart: 'numalgo 0'
      })
    })

    it('rejects malformed did:peer strings with invalidDid', async () => {
      const didPeer = driver()
      await rejectsWith(didPeer.get({ did: 'did:peer:' }), {
        name: 'DIDResolutionError',
        code: 'invalidDid'
      })
      await rejectsWith(didPeer.get({ did: 'did:peer:x' }), {
        name: 'DIDResolutionError',
        code: 'invalidDid'
      })
      await rejectsWith(didPeer.get({ did: 'did:peer:4garbage' }), {
        name: 'DIDResolutionError',
        code: 'invalidDid'
      })
      const tampered =
        longForm.slice(0, -1) + (longForm.endsWith('a') ? 'b' : 'a')
      await rejectsWith(didPeer.get({ did: tampered }), {
        name: 'DIDResolutionError',
        code: 'invalidDid'
      })
      const tooLong = longForm + 'a'.repeat(MAX_LONG_FORM_LENGTH)
      await rejectsWith(didPeer.get({ did: tooLong }), {
        name: 'DIDResolutionError',
        code: 'invalidDid'
      })
    })

    it('handles DID URL parts: query and path stripped, fragment honoured', async () => {
      const didPeer = driver()
      const node = (await didPeer.get({
        did: `${longForm}?service=didcomm#1`
      })) as any
      expect(node.id).toBe(`${longForm}#1`)
      const doc = (await didPeer.get({ did: `${longForm}/path` })) as any
      expect(doc.id).toBe(longForm)
      const trailing = (await didPeer.get({ did: `${longForm}#` })) as any
      expect(trailing.id).toBe(longForm)
      await rejectsWith(didPeer.get({ did: `${longForm}#a#b` }), {
        name: 'DIDResolutionError',
        code: 'invalidDidUrl'
      })
    })

    it('dereferences a key node with absolute id, controller and @context', async () => {
      const didPeer = driver()
      const node = (await didPeer.get({ url: `${longForm}#1` })) as any
      expect(node).toEqual({
        '@context': 'https://w3id.org/security/suites/ed25519-2018/v1',
        id: `${longForm}#1`,
        type: 'Ed25519VerificationKey2018',
        publicKeyBase58: 'AU2FFjtkVzjFuirgWieqGGqtNrAZWS9LDuB8TDp6EUrG',
        controller: longForm
      })
      // and a service node, with the document context as fallback
      const service = (await didPeer.get({ url: `${longForm}#didcomm` })) as any
      expect(service['@context']).toBe('https://w3id.org/did/v1')
      expect(service.type).toBe('did-communication')
    })

    it('returns a cloned node', async () => {
      const didPeer = driver()
      const first = (await didPeer.get({ url: `${longForm}#1` })) as any
      first.publicKeyBase58 = 'tampered'
      const second = (await didPeer.get({ url: `${longForm}#1` })) as any
      expect(second.publicKeyBase58).not.toBe('tampered')
    })

    it('unknown fragment is VerificationMethodError notFound', async () => {
      const error = await rejectsWith(
        driver().get({ url: `${longForm}#nope` }),
        {
          name: 'VerificationMethodError',
          code: 'notFound'
        }
      )
      expect((error as any).verificationMethod).toBe(`${longForm}#nope`)
    })

    it('a legacy publicKey entry is not dereferenceable', async () => {
      const v6 = vectors.find(v => v.name === 'examples/3.json')!
      await rejectsWith(
        driver().get({
          url: `${v6.longForm}#z6MkrmNwty5ajKtFqc1U48oL2MMLjWjartwc5sf2AihZwXDN`
        }),
        { name: 'VerificationMethodError', code: 'notFound' }
      )
    })

    it('a fragment shared by a method and a service returns the method', async () => {
      const inputDocument = {
        verificationMethod: [
          { id: '#x', type: 'Multikey', publicKeyMultibase: SEED_KEY }
        ],
        service: [{ id: '#x', type: 'S', serviceEndpoint: 'https://e' }]
      }
      const did = encodeLongForm({ inputDocument })
      const node = (await driver().get({ url: `${did}#x` })) as any
      expect(node.type).toBe('Multikey')
    })

    it('a type outside the table in a document without @context yields a node without one', async () => {
      const did = encodeLongForm({
        inputDocument: {
          verificationMethod: [
            { id: '#x', type: 'Mystery', publicKeyHex: '00' }
          ]
        }
      })
      const node = (await driver().get({ url: `${did}#x` })) as any
      expect(node).not.toHaveProperty('@context')
      expect(node.id).toBe(`${did}#x`)
    })

    it('short form without a store is notFound', async () => {
      await rejectsWith(driver().get({ did: shortForm }), {
        name: 'DIDResolutionError',
        code: 'notFound',
        messagePart: 'has not been seen'
      })
    })

    it('short form resolves after a long form get with a Map store', async () => {
      const store = new Map<string, string>()
      const didPeer = driver({ longFormStore: store })
      await didPeer.get({ did: longForm })
      expect(store.get(shortForm)).toBe(longForm)
      const doc = (await didPeer.get({ did: shortForm })) as any
      expect(doc.id).toBe(shortForm)
      expect(doc.alsoKnownAs).toEqual([longForm])
      expect(doc.verificationMethod[0].id).toBe(`${shortForm}#1`)
      expect(doc.verificationMethod[0].controller).toBe(shortForm)
      expect(doc.authentication).toEqual([`${shortForm}#1`])
      const node = (await didPeer.get({ url: `${shortForm}#1` })) as any
      expect(node.id).toBe(`${shortForm}#1`)
      expect(node.controller).toBe(shortForm)
    })

    it('rememberOnResolve: false leaves the store alone on get, generate still writes', async () => {
      const store = new Map<string, string>()
      const didPeer = makeDriver({
        longFormStore: store,
        rememberOnResolve: false
      })
      await didPeer.get({ did: longForm })
      expect(store.size).toBe(0)
      await rejectsWith(didPeer.get({ did: shortForm }), {
        name: 'DIDResolutionError',
        code: 'notFound'
      })
      const { didDocument } = await didPeer.generate()
      const generated = (didDocument as any).id as string
      expect(store.get(longToShort({ did: generated }))).toBe(generated)
      const doc = (await didPeer.get({
        did: longToShort({ did: generated })
      })) as any
      expect(doc.id).toBe(longToShort({ did: generated }))
    })
  })

  describe('LongFormStore semantics', () => {
    const vector = vectors.find(v => v.name === 'examples/1.json')!
    const other = vectors.find(v => v.name === 'examples/0.json')!

    it('a rejected set makes generate() reject with the cause', async () => {
      const failure = new Error('disk full')
      const store: LongFormStore = {
        get: () => undefined,
        set: async () => {
          throw failure
        }
      }
      const didPeer = makeDriver({ longFormStore: store })
      const error = await rejectsWith(didPeer.generate(), { name: 'Error' })
      expect(error.cause).toBe(failure)
    })

    it('a rejected set during a long form get is internalError with cause', async () => {
      const failure = new Error('disk full')
      const store: LongFormStore = {
        get: () => undefined,
        set: () => Promise.reject(failure)
      }
      const error = await rejectsWith(
        driver({ longFormStore: store }).get({ did: vector.longForm }),
        { name: 'DIDResolutionError', code: 'internalError' }
      )
      expect(error.cause).toBe(failure)
    })

    it('a rejected get is internalError, not notFound', async () => {
      const failure = new Error('db closed')
      const store: LongFormStore = {
        get: async () => {
          throw failure
        },
        set: () => undefined
      }
      const error = await rejectsWith(
        driver({ longFormStore: store }).get({ did: vector.shortForm }),
        { name: 'DIDResolutionError', code: 'internalError' }
      )
      expect(error.cause).toBe(failure)
    })

    it('a non-string store value is a miss', async () => {
      const store = { get: () => 42 as any, set: () => undefined }
      await rejectsWith(
        driver({ longFormStore: store }).get({ did: vector.shortForm }),
        { name: 'DIDResolutionError', code: 'notFound' }
      )
      const empty = { get: () => '', set: () => undefined }
      await rejectsWith(
        driver({ longFormStore: empty }).get({ did: vector.shortForm }),
        { name: 'DIDResolutionError', code: 'notFound' }
      )
    })

    it('a stored long form of a different DID is invalidDid', async () => {
      const store = new Map([[vector.shortForm, other.longForm]])
      await rejectsWith(
        driver({ longFormStore: store }).get({ did: vector.shortForm }),
        {
          name: 'DIDResolutionError',
          code: 'invalidDid',
          messagePart: 'different DID'
        }
      )
    })

    it('a stored value that is not a long form is internalError', async () => {
      const corrupt = new Map([[vector.shortForm, 'did:peer:4zQmgarbage']])
      await rejectsWith(
        driver({ longFormStore: corrupt }).get({ did: vector.shortForm }),
        {
          name: 'DIDResolutionError',
          code: 'internalError',
          messagePart: 'not a did:peer numalgo 4 long form'
        }
      )
    })

    it('an async store: generate() then an immediate short form get hits', async () => {
      const backing = new Map<string, string>()
      const store: LongFormStore = {
        get: async key => backing.get(key),
        set: async (key, value) => {
          await new Promise(resolve => setTimeout(resolve, 5))
          backing.set(key, value)
        }
      }
      const didPeer = makeDriver({ longFormStore: store })
      const { didDocument } = await didPeer.generate()
      const longForm = (didDocument as any).id as string
      const shortForm = longToShort({ did: longForm })
      const doc = (await didPeer.get({ did: shortForm })) as any
      expect(doc.id).toBe(shortForm)
    })

    it('generate({ seed }) twice writes the same entry', async () => {
      const writes: Array<[string, string]> = []
      const store: LongFormStore = {
        get: () => undefined,
        set: (key, value) => writes.push([key, value])
      }
      const didPeer = makeDriver({ longFormStore: store })
      await didPeer.generate({ seed: SEED })
      await didPeer.generate({ seed: SEED })
      expect(writes).toHaveLength(2)
      expect(writes[0]).toEqual(writes[1])
    })
  })

  describe('publicMethodFor()', () => {
    let didPeer: DidPeerDriver
    beforeEach(() => {
      didPeer = driver()
      didPeer.use({
        keyPairClass: Ed25519VerificationKey,
        enableEncryptionKeyDerivation: true
      })
    })

    it('returns the node for each purpose without @context', async () => {
      const { didDocument } = await didPeer.generate()
      for (const purpose of [
        'authentication',
        'assertionMethod',
        'capabilityDelegation',
        'capabilityInvocation',
        'keyAgreement'
      ]) {
        const method = didPeer.publicMethodFor({ didDocument, purpose }) as any
        expect(method.id.startsWith((didDocument as any).id + '#')).toBe(true)
        expect(method).not.toHaveProperty('@context')
      }
      expect(() => didPeer.publicMethodFor({ didDocument })).toThrow(TypeError)
      expect(() => didPeer.publicMethodFor({ purpose: 'x' })).toThrow(TypeError)
      expect(() =>
        didPeer.publicMethodFor({
          didDocument: { id: 'did:x' } as any,
          purpose: 'authentication'
        })
      ).toThrow(/No verification method found/)
    })
  })
})
