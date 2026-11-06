/**
 * Browser test entry, served by the Vite dev server so that bare package
 * specifiers resolve. The Playwright spec imports this module from
 * `page.evaluate` and calls `run()`.
 */
import { CachedResolver } from '@interop/did-io'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import jsigs from '@interop/jsonld-signatures'
import { securityLoader } from '@interop/security-document-loader'
import { driver, longToShort } from '../../src/index.js'

export async function run(): Promise<Record<string, unknown>> {
  const didPeer = driver({ longFormStore: new Map() })
  didPeer.use({
    keyPairClass: Ed25519VerificationKey,
    enableEncryptionKeyDerivation: true
  })
  const resolver = new CachedResolver()
  resolver.use(didPeer)
  const { didDocument, methodFor } = await didPeer.generate()
  const doc = didDocument as any
  const did = doc.id as string
  const node = (await resolver.get({
    url: methodFor({ purpose: 'authentication' }).id!
  })) as any
  const short = (await resolver.get({ did: longToShort({ did }) })) as any

  const documentLoader = securityLoader({
    didResolver: resolver as any
  }).build()
  const { AssertionProofPurpose } = (jsigs as any).purposes
  const signed = await jsigs.sign(
    {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: 'urn:uuid:1',
      type: ['VerifiableCredential'],
      issuer: did,
      issuanceDate: '2026-11-05T00:00:00Z',
      credentialSubject: { id: 'did:example:subject' }
    },
    {
      suite: new Ed25519Signature2020({
        signer: methodFor({ purpose: 'assertionMethod' }).signer()
      }),
      purpose: new AssertionProofPurpose(),
      documentLoader
    }
  )
  const verification = await jsigs.verify(signed, {
    suite: new Ed25519Signature2020(),
    purpose: new AssertionProofPurpose(),
    documentLoader
  })
  return {
    did,
    keyAgreementCount: doc.keyAgreement.length,
    nodeId: node.id,
    shortId: short.id,
    verified: verification.verified,
    error: verification.error ? String(verification.error) : undefined
  }
}
