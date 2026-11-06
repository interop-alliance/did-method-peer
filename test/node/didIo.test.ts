/**
 * did-io integration and end-to-end proof verification: the driver behind
 * `CachedResolver`, a Data Integrity proof signed by a did:peer key and
 * verified through jsonld-signatures' controller proof purposes, and a zcap
 * delegated and invoked by a did:peer controller.
 */
import { describe, it, expect, beforeAll } from 'vitest'
import { CachedResolver } from '@interop/did-io'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import jsigs from '@interop/jsonld-signatures'
import { securityLoader } from '@interop/security-document-loader'
import {
  CapabilityDelegation,
  CapabilityInvocation,
  createRootCapability,
  constants as zcapConstants
} from '@interop/zcap'
import { driver, longToShort } from '../../src/index.js'
import type { DidPeerDriver } from '../../src/index.js'
import vectors from '../fixtures/test-vectors.json' with { type: 'json' }

const {
  purposes: { AssertionProofPurpose, AuthenticationProofPurpose }
} = jsigs as any

function setup({ store = new Map<string, string>() } = {}) {
  const didPeer = driver({ longFormStore: store })
  didPeer.use({
    keyPairClass: Ed25519VerificationKey,
    enableEncryptionKeyDerivation: true
  })
  const resolver = new CachedResolver()
  resolver.use(didPeer)
  return { didPeer, resolver, store }
}

/**
 * A documentLoader serving the bundled security contexts, did:peer documents
 * and key nodes through the resolver, and any statically registered document
 * (root capabilities) first.
 */
function buildLoader(resolver: CachedResolver) {
  const statics = new Map<string, unknown>()
  const built = securityLoader({ didResolver: resolver as any }).build()
  const documentLoader = async (url: string): Promise<any> => {
    const doc = statics.get(url)
    if (doc !== undefined) {
      return {
        contextUrl: null,
        document: structuredClone(doc),
        documentUrl: url
      }
    }
    return built(url)
  }
  return { documentLoader, statics }
}

describe('did-io integration', () => {
  const vector = vectors.find(v => v.name === 'examples/2.json')!

  it('resolves documents and key nodes through CachedResolver', async () => {
    const { resolver } = setup()
    const doc = (await resolver.get({ did: vector.longForm })) as any
    expect(doc.id).toBe(vector.longForm)
    const node = (await resolver.get({
      url: `${vector.longForm}#key-1`
    })) as any
    expect(node.id).toBe(`${vector.longForm}#key-1`)
    expect(node['@context']).toBe(
      'https://w3id.org/security/suites/ed25519-2020/v1'
    )
  })

  it('resolveDID envelopes: long form, short form miss, numalgo 2, did:key', async () => {
    const { resolver } = setup()
    const ok = await resolver.resolveDID({ did: vector.longForm })
    expect(ok.didResolutionMetadata).toEqual({})
    expect((ok.didDocument as any).id).toBe(vector.longForm)

    // A fresh resolver: the long form resolution above wrote the store.
    const miss = await setup().resolver.resolveDID({ did: vector.shortForm })
    expect(miss.didDocument).toBeNull()
    expect(miss.didResolutionMetadata.error).toBe('notFound')
    expect(miss.didResolutionMetadata.problemDetails?.type).toBe(
      'https://www.w3.org/ns/did#NOT_FOUND'
    )

    const numalgo2 = await resolver.resolveDID({ did: 'did:peer:2.Ez6LSabc' })
    expect(numalgo2.didResolutionMetadata.error).toBe('methodNotSupported')

    const didKey = await resolver.resolveDID({ did: 'did:key:z6Mkabc' })
    expect(didKey.didResolutionMetadata.error).toBe('methodNotSupported')
  })

  it('generates through CachedResolver.generate({ method: "peer" })', async () => {
    const { resolver, store } = setup()
    const { didDocument, keyPairs, methodFor } = await resolver.generate({
      method: 'peer'
    })
    const longForm = (didDocument as any).id as string
    expect(longForm.startsWith('did:peer:4')).toBe(true)
    expect(keyPairs.size).toBe(2)
    expect(methodFor({ purpose: 'authentication' }).controller).toBe(longForm)
    expect(store.get(longToShort({ did: longForm }))).toBe(longForm)
    const short = (await resolver.get({
      did: longToShort({ did: longForm })
    })) as any
    expect(short.id).toBe(longToShort({ did: longForm }))
  })

  it('short form notFound, then long form, then short form resolves within the cache TTL', async () => {
    const { resolver } = setup()
    const miss = await resolver.resolveDID({ did: vector.shortForm })
    expect(miss.didResolutionMetadata.error).toBe('notFound')
    await expect(resolver.get({ did: vector.shortForm })).rejects.toMatchObject(
      {
        code: 'notFound'
      }
    )
    await resolver.get({ did: vector.longForm })
    const doc = (await resolver.get({ did: vector.shortForm })) as any
    expect(doc.id).toBe(vector.shortForm)
  })
})

describe('end to end: Data Integrity proofs by a did:peer key', () => {
  let didPeer: DidPeerDriver
  let resolver: CachedResolver
  let documentLoader: (url: string) => Promise<any>
  let statics: Map<string, unknown>
  let generated: Awaited<ReturnType<DidPeerDriver['generate']>>
  let did: string

  beforeAll(async () => {
    ;({ didPeer, resolver } = setup())
    ;({ documentLoader, statics } = buildLoader(resolver))
    generated = await didPeer.generate()
    did = (generated.didDocument as any).id
  })

  function credential() {
    return {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: `urn:uuid:${crypto.randomUUID()}`,
      type: ['VerifiableCredential'],
      issuer: did,
      issuanceDate: '2026-11-05T00:00:00Z',
      credentialSubject: { id: 'did:example:subject' }
    }
  }

  it('signs and verifies for assertionMethod', async () => {
    const keyPair = generated.methodFor({ purpose: 'assertionMethod' })
    const signed = await jsigs.sign(credential(), {
      suite: new Ed25519Signature2020({ signer: keyPair.signer() }),
      purpose: new AssertionProofPurpose(),
      documentLoader
    })
    expect((signed as any).proof.verificationMethod).toBe(keyPair.id)
    expect(keyPair.id!.startsWith(did + '#')).toBe(true)
    const result = await jsigs.verify(signed, {
      suite: new Ed25519Signature2020(),
      purpose: new AssertionProofPurpose(),
      documentLoader
    })
    expect(result.error).toBeUndefined()
    expect(result.verified).toBe(true)
  })

  it('signs and verifies for authentication', async () => {
    const keyPair = generated.methodFor({ purpose: 'authentication' })
    const signed = await jsigs.sign(credential(), {
      suite: new Ed25519Signature2020({ signer: keyPair.signer() }),
      purpose: new AuthenticationProofPurpose({
        challenge: 'abc',
        domain: 'example.com'
      }),
      documentLoader
    })
    const result = await jsigs.verify(signed, {
      suite: new Ed25519Signature2020(),
      purpose: new AuthenticationProofPurpose({
        challenge: 'abc',
        domain: 'example.com'
      }),
      documentLoader
    })
    expect(result.error).toBeUndefined()
    expect(result.verified).toBe(true)
  })

  it('fails authorization when the proof names a purpose the key does not serve', async () => {
    // Build a DID whose key is authentication-only, then sign an assertion.
    const keyPair = await Ed25519VerificationKey.generate()
    const { methodFor } = await didPeer.generate({
      verificationMethods: [{ keyPair, purposes: ['authentication'] }]
    })
    const signer = methodFor({ purpose: 'authentication' }).signer()
    const signed = await jsigs.sign(credential(), {
      suite: new Ed25519Signature2020({ signer }),
      purpose: new AssertionProofPurpose(),
      documentLoader
    })
    const result = await jsigs.verify(signed, {
      suite: new Ed25519Signature2020(),
      purpose: new AssertionProofPurpose(),
      documentLoader
    })
    expect(result.verified).toBe(false)
  })

  it('delegates and invokes a zcap controlled by the did:peer DID', async () => {
    const invocationTarget = `urn:uuid:${crypto.randomUUID()}`
    const root = createRootCapability({ controller: did, invocationTarget })
    statics.set(root.id, root)

    const delegate = await didPeer.generate()
    const delegateDid = (delegate.didDocument as any).id as string

    const delegated = await jsigs.sign(
      {
        '@context': zcapConstants.ZCAP_CONTEXT_URL,
        id: `urn:uuid:${crypto.randomUUID()}`,
        controller: delegateDid,
        parentCapability: root.id,
        invocationTarget,
        expires: '3000-01-01T00:00:00Z'
      },
      {
        suite: new Ed25519Signature2020({
          signer: generated
            .methodFor({ purpose: 'capabilityDelegation' })
            .signer()
        }),
        purpose: new CapabilityDelegation({ parentCapability: root }),
        documentLoader
      }
    )

    const verifiedDelegation = await jsigs.verify(delegated, {
      suite: new Ed25519Signature2020(),
      purpose: new CapabilityDelegation({
        suite: new Ed25519Signature2020(),
        expectedRootCapability: root.id
      }),
      documentLoader
    })
    expect(verifiedDelegation.error).toBeUndefined()
    expect(verifiedDelegation.verified).toBe(true)

    const invocation = await jsigs.sign(
      {
        '@context': zcapConstants.ZCAP_CONTEXT_URL,
        id: 'urn:x:doc',
        controller: delegateDid
      },
      {
        suite: new Ed25519Signature2020({
          signer: delegate
            .methodFor({ purpose: 'capabilityInvocation' })
            .signer()
        }),
        purpose: new CapabilityInvocation({
          capability: delegated as any,
          capabilityAction: 'read',
          invocationTarget
        }),
        documentLoader
      }
    )
    const verifiedInvocation = await jsigs.verify(invocation, {
      suite: new Ed25519Signature2020(),
      purpose: new CapabilityInvocation({
        suite: new Ed25519Signature2020(),
        expectedTarget: invocationTarget,
        expectedRootCapability: root.id,
        expectedAction: 'read'
      }),
      documentLoader
    })
    expect(verifiedInvocation.error).toBeUndefined()
    expect(verifiedInvocation.verified).toBe(true)
  })
})
