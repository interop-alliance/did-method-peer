/**
 * Shared types for the did:peer driver: the key suite registry shapes (the
 * same contract `@interop/did-method-key` and `@interop/did-web-resolver`
 * use, so one suite registers with every did-io driver), the input document
 * type, and the `LongFormStore` the driver consults to resolve short forms.
 */
import type { AbstractKeyPair } from '@interop/data-integrity-core'

/**
 * The id-less, relative-reference document a did:peer numalgo 4 DID is derived
 * from. The codec never inspects its shape beyond what contextualization
 * needs, so it is a plain JSON object.
 */
export type InputDocument = Record<string, unknown>

/**
 * A multibase-multikey deserializer: converts a `{publicKeyMultibase}` value
 * into a live key pair instance.
 */
export type FromMultibase = (options: {
  publicKeyMultibase: string
}) => Promise<AbstractKeyPair>

/**
 * A key suite class usable for did:peer generation and key rebuilding via
 * `DidPeerDriver.use({ keyPairClass })`. The static `multibaseHeader` (the
 * 4-character multibase-multikey prefix, e.g. `z6Mk` for Ed25519) lets the
 * driver register the suite without the caller knowing that prefix.
 */
export interface KeyPairClass {
  multibaseHeader: string
  from: FromMultibase
  generate?: (options?: object) => Promise<AbstractKeyPair>
}

/**
 * An entry in the driver's registry of key suites, keyed by multibase header.
 */
export interface RegisteredKeyType {
  fromMultibase: FromMultibase
  generate?: (options?: object) => Promise<AbstractKeyPair>
  enableEncryptionKeyDerivation?: boolean
}

/**
 * The driver's memory of long forms, keyed by short form. A short form is only
 * a hash, so it resolves only after its long form has been seen; the driver
 * writes `set(shortForm, longForm)` from `generate()` and (with
 * `rememberOnResolve`) from a successful long form `get()`, and reads
 * `get(shortForm)` for a short form. Positional parameters, so that a plain
 * `Map<string, string>` satisfies the interface and a persistent store returns
 * promises from the same two methods. The driver never deletes; a store grows
 * by one entry per distinct long form resolved, and the store implementer owns
 * bounds and eviction.
 */
export interface LongFormStore {
  get(shortForm: string): string | undefined | Promise<string | undefined>
  set(shortForm: string, longForm: string): unknown
}

/**
 * Constructor options for `DidPeerDriver` and `driver()`.
 */
export interface DidPeerDriverOptions {
  longFormStore?: LongFormStore
  /**
   * Whether a successful long form `get()` writes the long form store so the
   * counterpart's short form resolves later. Default `true`; a verifier that
   * only fetches key nodes sets it to `false`. `generate()` writes regardless.
   */
  rememberOnResolve?: boolean
}
