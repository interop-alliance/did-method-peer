/**
 * `DidPeerDriver`: the `@interop/did-io` method driver for did:peer numalgo 4.
 * Generates DIDs from key pairs, a seed or a caller-supplied input document,
 * resolves long forms offline and short forms through the configured
 * `LongFormStore`, dereferences verification method and service nodes by DID
 * URL, and performs reference resolution so the documents it returns carry
 * absolute DID URLs like did:key and did:web documents do.
 */
import { decodeSecretKeySeed } from '@interop/bnid'
import {
  contextsBySuite,
  deepClone,
  findVerificationMethod
} from '@interop/did-io'
import type { DidGenerationResult, DidMethodDriver } from '@interop/did-io'
import {
  VerificationMethodError,
  type AbstractKeyPair,
  type IDIDDocument,
  type IKeyPair,
  type IPublicKey,
  type IVerificationMethodEntry
} from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import {
  DEFAULT_PURPOSES,
  DID_CONTEXT_URL,
  DID_PEER_PREFIX
} from './constants.js'
import {
  addThirdPartyMethod,
  addVerificationMethod,
  validateInputDocument
} from './inputDocument.js'
import {
  encodeLongForm,
  isLongForm,
  isShortForm,
  longToShort,
  resolutionError,
  resolveLongForm,
  resolveShortForm
} from './numalgo4.js'
import {
  METHOD_PROPERTIES,
  RESOURCE_PROPERTIES,
  findResource,
  isPlainObject
} from './resources.js'
import type {
  DidPeerDriverOptions,
  FromMultibase,
  InputDocument,
  KeyPairClass,
  LongFormStore,
  RegisteredKeyType
} from './types.js'

const ED25519_MULTIKEY_HEADER = 'z6Mk'
const X25519_MULTIKEY_HEADER = 'z6LS'
const X25519_TYPES = new Set([
  'X25519KeyAgreementKey2019',
  'X25519KeyAgreementKey2020'
])

type LiveEntry = {
  keyPair: AbstractKeyPair | IKeyPair
  fragment?: string
  purposes?: string[]
}

/**
 * A third-party method with explicit purposes. A bare
 * `IVerificationMethodEntry` gets the four default purposes instead.
 */
type ThirdPartyEntry = {
  method: IVerificationMethodEntry
  purposes: string[]
}

/**
 * `generate()` options. The three entry paths are mutually exclusive:
 * `inputDocument` (with optional `keyPairs`), `seed`, or explicit key pairs.
 */
export interface GenerateOptions {
  inputDocument?: InputDocument
  keyPairs?: Map<string, AbstractKeyPair>
  seed?: string | Uint8Array
  keyType?: KeyPairClass | string
  verificationKeyPair?: AbstractKeyPair | IKeyPair
  keyAgreementKeyPair?: AbstractKeyPair | IKeyPair
  verificationMethods?: Array<
    LiveEntry | ThirdPartyEntry | IVerificationMethodEntry
  >
  service?: object[]
}

function isLiveEntry(
  entry: LiveEntry | ThirdPartyEntry | IVerificationMethodEntry
): entry is LiveEntry {
  return isPlainObject(entry) && 'keyPair' in entry
}

function isThirdPartyEntry(
  entry: ThirdPartyEntry | IVerificationMethodEntry
): entry is ThirdPartyEntry {
  return isPlainObject(entry) && 'method' in entry && 'purposes' in entry
}

/**
 * Rewrites a contextualized document's relative ids and relationship
 * references to absolute DID URLs against `did` (DID Core's relative DID URL
 * rule). Touches the `id` of object entries in `verificationMethod`, the five
 * relationships and `service`, and string entries in the five relationships.
 * Already-absolute values are left alone. Mutates in place; callers pass the
 * fresh copy the codec returned.
 */
function resolveReferences({
  didDocument,
  did
}: {
  didDocument: IDIDDocument
  did: string
}): IDIDDocument {
  const doc = didDocument as unknown as Record<string, unknown>
  const absolute = (value: unknown): unknown =>
    typeof value === 'string' && value.startsWith('#')
      ? `${did}${value}`
      : value
  for (const property of RESOURCE_PROPERTIES) {
    const entries = doc[property]
    if (!Array.isArray(entries)) {
      continue
    }
    for (let index = 0; index < entries.length; index++) {
      const entry = entries[index]
      if (isPlainObject(entry)) {
        entry.id = absolute(entry.id)
      } else if (property !== 'verificationMethod' && property !== 'service') {
        entries[index] = absolute(entry)
      }
    }
  }
  return didDocument
}

/**
 * Decodes a secret key seed: a bnid multibase/multihash string (`z1A...`) or
 * a `Uint8Array` of exactly 32 bytes.
 */
function decodeSeed(seed: string | Uint8Array): Uint8Array {
  if (typeof seed === 'string') {
    if (!seed.startsWith('z1A')) {
      throw new TypeError(
        '"seed" parameter must be a multibase/multihash encoded string, or a ' +
          'Uint8Array.'
      )
    }
    return decodeSecretKeySeed({ secretKeySeed: seed })
  }
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new TypeError('"seed" must be a Uint8Array of exactly 32 bytes.')
  }
  return new Uint8Array(seed)
}

export class DidPeerDriver implements DidMethodDriver {
  public method: string
  public longFormStore?: LongFormStore
  public rememberOnResolve: boolean
  public _allowedKeyTypes: Map<string, RegisteredKeyType>

  /**
   * @param options {object}
   * @param [options.longFormStore] {LongFormStore} - Where long forms are
   *   remembered so short forms resolve. A `Map` works for in-memory use.
   *   Without one, every short form is `notFound`.
   * @param [options.rememberOnResolve=true] {boolean} - Whether a successful
   *   long form `get()` writes the store. `generate()` always writes.
   */
  constructor({
    longFormStore,
    rememberOnResolve = true
  }: DidPeerDriverOptions = {}) {
    this.method = 'peer'
    this.longFormStore = longFormStore
    this.rememberOnResolve = rememberOnResolve
    this._allowedKeyTypes = new Map()
  }

  /**
   * Registers a key suite for generation and key rebuilding.
   *
   * Preferred form: pass a `keyPairClass` exposing static `multibaseHeader`,
   * `from` and (optionally) `generate`. Lower-level form: pass
   * `multibaseMultikeyHeader` plus a `fromMultibase` deserializer; suites
   * registered this way cannot `generate()`.
   *
   * @param options {object}
   * @param [options.keyPairClass] {KeyPairClass}
   * @param [options.multibaseMultikeyHeader] {string}
   * @param [options.fromMultibase] {FromMultibase}
   * @param [options.enableEncryptionKeyDerivation=false] {boolean} - When
   *   `true`, generating with this (Ed25519) suite also derives an X25519
   *   `keyAgreement` key from the verification key. Off by default, since
   *   reusing one key for signing and key agreement is a posture choice.
   */
  use({
    keyPairClass,
    multibaseMultikeyHeader,
    fromMultibase,
    enableEncryptionKeyDerivation = false
  }: {
    keyPairClass?: KeyPairClass
    multibaseMultikeyHeader?: string
    fromMultibase?: FromMultibase
    enableEncryptionKeyDerivation?: boolean
  } = {}): void {
    if (keyPairClass) {
      const header = keyPairClass.multibaseHeader
      if (!(header && typeof header === 'string')) {
        throw new TypeError('"keyPairClass.multibaseHeader" must be a string.')
      }
      if (typeof keyPairClass.from !== 'function') {
        throw new TypeError('"keyPairClass.from" must be a function.')
      }
      this._allowedKeyTypes.set(header, {
        fromMultibase: keyPairClass.from.bind(keyPairClass),
        generate:
          typeof keyPairClass.generate === 'function'
            ? keyPairClass.generate.bind(keyPairClass)
            : undefined,
        enableEncryptionKeyDerivation
      })
      return
    }
    if (
      !multibaseMultikeyHeader ||
      typeof multibaseMultikeyHeader !== 'string'
    ) {
      throw new TypeError('"multibaseMultikeyHeader" must be a string.')
    }
    if (typeof fromMultibase !== 'function') {
      throw new TypeError('"fromMultibase" must be a function.')
    }
    this._allowedKeyTypes.set(multibaseMultikeyHeader, {
      fromMultibase,
      enableEncryptionKeyDerivation
    })
  }

  /**
   * Generates a did:peer numalgo 4 DID. Three mutually exclusive entry paths:
   *
   * 1. `inputDocument`: validated, encoded and resolved as given. `keyPairs`
   *    (keyed by bare fragment) binds live pairs to the document's methods;
   *    a fragment with no method, or a public key that differs, is a
   *    `TypeError`.
   * 2. `seed`: one key pair is derived with the selected or sole registered
   *    suite, then as path 3.
   * 3. Explicit or random key pairs: `verificationKeyPair` (or a fresh random
   *    pair) gets the four default purposes; `keyAgreementKeyPair` gets
   *    `keyAgreement`, or an X25519 key is derived when the suite was
   *    registered with `enableEncryptionKeyDerivation`; `verificationMethods`
   *    entries (`{ keyPair, fragment?, purposes? }`, `{ method, purposes }`
   *    for a third-party method with explicit purposes, or a bare third-party
   *    reference / method object with the default four) are added in order;
   *    `service` is copied.
   *
   * Every path binds the live pairs (`controller` and `id` set to the long
   * form), writes the long form store when one is configured, and returns the
   * did-io generation result. `didDocument.id` is the long form.
   *
   * @param [options] {GenerateOptions}
   *
   * @returns {Promise<DidGenerationResult>}
   */
  async generate(options: GenerateOptions = {}): Promise<DidGenerationResult> {
    return this._generate(options, { remember: true })
  }

  async _generate(
    {
      inputDocument,
      keyPairs,
      seed,
      keyType,
      verificationKeyPair,
      keyAgreementKeyPair,
      verificationMethods,
      service
    }: GenerateOptions,
    { remember }: { remember: boolean }
  ): Promise<DidGenerationResult> {
    if (keyPairs && !inputDocument) {
      throw new TypeError('"keyPairs" requires an "inputDocument".')
    }
    if (
      inputDocument &&
      (seed !== undefined ||
        keyType !== undefined ||
        verificationKeyPair ||
        keyAgreementKeyPair ||
        verificationMethods ||
        service)
    ) {
      throw new TypeError(
        '"inputDocument" cannot be combined with "seed", "keyType", ' +
          '"verificationKeyPair", "keyAgreementKeyPair", ' +
          '"verificationMethods" or "service".'
      )
    }
    if (seed !== undefined && verificationKeyPair) {
      throw new TypeError(
        '"seed" and "verificationKeyPair" are two sources for one key; pass one.'
      )
    }
    if (keyType !== undefined && verificationKeyPair) {
      throw new TypeError(
        '"keyType" has no effect with an explicit "verificationKeyPair".'
      )
    }

    // Live pairs to bind after the long form is known, by bare fragment.
    const livePairs = new Map<string, AbstractKeyPair>()
    let document: InputDocument

    if (inputDocument) {
      document = inputDocument
      validateInputDocument({ inputDocument: document })
      for (const [fragment, pair] of keyPairs ?? []) {
        await this._assertPairMatchesMethod({
          inputDocument: document,
          fragment,
          pair
        })
        livePairs.set(fragment, pair)
      }
    } else {
      document = { '@context': [DID_CONTEXT_URL] }
      let verificationPair: AbstractKeyPair | undefined
      if (seed !== undefined) {
        verificationPair = await this._generateKeyPair({ seed, keyType })
      } else if (verificationKeyPair) {
        verificationPair = await this._toKeyPair(verificationKeyPair)
      } else if (!verificationMethods && !keyAgreementKeyPair) {
        verificationPair = await this._generateKeyPair({ keyType })
      }
      if (verificationPair) {
        const { fragment } = await addVerificationMethod({
          inputDocument: document,
          keyPair: verificationPair,
          purposes: DEFAULT_PURPOSES
        })
        livePairs.set(fragment, verificationPair)
      }
      let agreementPair: AbstractKeyPair | undefined
      if (keyAgreementKeyPair) {
        agreementPair = await this._toKeyPair(keyAgreementKeyPair)
      } else if (verificationPair) {
        agreementPair = this._deriveKeyAgreementKey(verificationPair)
      }
      if (agreementPair) {
        const { fragment } = await addVerificationMethod({
          inputDocument: document,
          keyPair: agreementPair,
          purposes: ['keyAgreement']
        })
        livePairs.set(fragment, agreementPair)
      }
      for (const entry of verificationMethods ?? []) {
        if (isLiveEntry(entry)) {
          const pair = await this._toKeyPair(entry.keyPair)
          const { fragment } = await addVerificationMethod({
            inputDocument: document,
            keyPair: pair,
            fragment: entry.fragment,
            purposes: entry.purposes ?? DEFAULT_PURPOSES
          })
          livePairs.set(fragment, pair)
        } else if (isThirdPartyEntry(entry)) {
          addThirdPartyMethod({
            inputDocument: document,
            entry: entry.method,
            purposes: entry.purposes
          })
        } else {
          addThirdPartyMethod({
            inputDocument: document,
            entry,
            purposes: DEFAULT_PURPOSES
          })
        }
      }
      if (service) {
        document.service = deepClone(service)
      }
      validateInputDocument({ inputDocument: document })
    }

    const longForm = encodeLongForm({ inputDocument: document })
    const shortForm = longToShort({ did: longForm })
    const didDocument = resolveReferences({
      didDocument: resolveLongForm({ did: longForm }),
      did: longForm
    })

    const boundPairs = new Map<string, AbstractKeyPair>()
    for (const [fragment, pair] of livePairs) {
      pair.controller = longForm
      pair.id = `${longForm}#${fragment}`
      boundPairs.set(pair.id, pair)
    }

    if (remember && this.longFormStore) {
      try {
        await this.longFormStore.set(shortForm, longForm)
      } catch (cause) {
        throw new Error(
          `Failed to write the long form store for "${shortForm}".`,
          { cause }
        )
      }
    }

    const methodFor = ({ purpose }: { purpose: string }): AbstractKeyPair => {
      const { id } = this.publicMethodFor({ didDocument, purpose })
      const pair = id === undefined ? undefined : boundPairs.get(id)
      if (!pair) {
        throw new Error(
          `No key pair available for verification method "${id}" (purpose "${purpose}").`
        )
      }
      return pair
    }

    return { didDocument, keyPairs: boundPairs, methodFor }
  }

  /**
   * Generates a did:peer DID from existing key pairs (live instances or plain
   * public key descriptions, rebuilt through the registered suites). With only
   * `keyAgreementKeyPair`, no signing key is generated.
   *
   * @param options {object}
   * @param [options.verificationKeyPair] {AbstractKeyPair | IKeyPair}
   * @param [options.keyAgreementKeyPair] {AbstractKeyPair | IKeyPair}
   *
   * @returns {Promise<DidGenerationResult>}
   */
  async fromKeyPair({
    verificationKeyPair,
    keyAgreementKeyPair
  }: {
    verificationKeyPair?: AbstractKeyPair | IKeyPair
    keyAgreementKeyPair?: AbstractKeyPair | IKeyPair
  } = {}): Promise<DidGenerationResult> {
    if (!(verificationKeyPair || keyAgreementKeyPair)) {
      throw new TypeError(
        '"verificationKeyPair" or "keyAgreementKeyPair" must be provided.'
      )
    }
    return this.generate({ verificationKeyPair, keyAgreementKeyPair })
  }

  /**
   * Converts a public key description to a did:peer DID document. An X25519
   * description becomes the `keyAgreement` key, anything else the
   * verification key. Unlike `generate()`, no `keyPairs` map is returned and
   * the long form store is not written.
   *
   * @param options {object}
   * @param options.publicKeyDescription {AbstractKeyPair | IKeyPair | IPublicKey}
   *
   * @returns {Promise<{didDocument: IDIDDocument}>}
   */
  async publicKeyToDidDoc({
    publicKeyDescription
  }: {
    publicKeyDescription?: AbstractKeyPair | IKeyPair | IPublicKey
  } = {}): Promise<{ didDocument: IDIDDocument }> {
    if (!publicKeyDescription) {
      throw new TypeError('"publicKeyDescription" is required.')
    }
    const keyPair = await this._toKeyPair(publicKeyDescription)
    const isKeyAgreement =
      X25519_TYPES.has(keyPair.type ?? '') ||
      (
        keyPair as { publicKeyMultibase?: string }
      ).publicKeyMultibase?.startsWith(X25519_MULTIKEY_HEADER) === true
    const { didDocument } = await this._generate(
      isKeyAgreement
        ? { keyAgreementKeyPair: keyPair }
        : { verificationKeyPair: keyPair },
      { remember: false }
    )
    return { didDocument }
  }

  /**
   * Resolves a did:peer numalgo 4 DID or DID URL. A long form resolves
   * offline; a short form resolves through the long form store. A `#fragment`
   * returns the verification method or service node with that id, cloned,
   * with an `@context`. A `?query` or `/path` is stripped and the authority
   * resolved.
   *
   * @param options {object}
   * @param [options.did] {string}
   * @param [options.url] {string} - Alias for `did`.
   *
   * @throws {DIDResolutionError} `methodNotSupported` for a non-did:peer DID
   *   or another numalgo; `invalidDid` for a malformed or tampered DID;
   *   `invalidDidUrl` for more than one `#`; `notFound` for a short form whose
   *   long form has not been seen; `internalError` for a store failure.
   * @throws {VerificationMethodError} `notFound` for an unknown fragment.
   *
   * @returns {Promise<IDIDDocument | IPublicKey>}
   */
  async get({
    did,
    url
  }: {
    did?: string
    url?: string
    [key: string]: unknown
  } = {}): Promise<IDIDDocument | IPublicKey> {
    did = did ?? url
    if (typeof did !== 'string' || did.length === 0) {
      throw new TypeError('A string "did" or "url" parameter is required.')
    }
    if (did.indexOf('#') !== did.lastIndexOf('#')) {
      throw resolutionError({
        code: 'invalidDidUrl',
        message: `DID URL "${did}" has more than one "#".`
      })
    }
    const hashIndex = did.indexOf('#')
    const beforeHash = hashIndex === -1 ? did : did.slice(0, hashIndex)
    const fragment = hashIndex === -1 ? '' : did.slice(hashIndex + 1)
    const authority = beforeHash.split(/[?/]/)[0] ?? ''

    if (!authority.startsWith(DID_PEER_PREFIX)) {
      throw resolutionError({
        code: 'methodNotSupported',
        message: `DID method not supported: "${authority}".`
      })
    }
    const numalgo = authority.charAt(DID_PEER_PREFIX.length)
    if (!/^[0-9]$/.test(numalgo)) {
      throw resolutionError({
        code: 'invalidDid',
        message: `Malformed did:peer DID (no numalgo digit): "${authority}".`
      })
    }
    if (numalgo !== '4') {
      throw resolutionError({
        code: 'methodNotSupported',
        message: `did:peer numalgo ${numalgo} is not supported; only numalgo 4 is.`
      })
    }

    let didDocument: IDIDDocument
    if (isLongForm(authority)) {
      didDocument = resolveLongForm({ did: authority })
      if (this.longFormStore && this.rememberOnResolve) {
        try {
          await this.longFormStore.set(
            longToShort({ did: authority }),
            authority
          )
        } catch (cause) {
          throw resolutionError({
            code: 'internalError',
            message: `Failed to write the long form store for "${authority}".`,
            cause
          })
        }
      }
    } else if (isShortForm(authority)) {
      didDocument = await this._resolveShortForm(authority)
    } else {
      throw resolutionError({
        code: 'invalidDid',
        message: `Malformed did:peer numalgo 4 DID: "${authority}".`
      })
    }
    resolveReferences({ didDocument, did: authority })

    if (!fragment) {
      return didDocument
    }
    const id = `${authority}#${fragment}`
    // The legacy `publicKey` array is not searched.
    const node = findResource({
      document: didDocument as unknown as Record<string, unknown>,
      id
    })
    if (!node) {
      throw new VerificationMethodError(
        `DID document entity with id "${id}" not found.`,
        { code: 'notFound', verificationMethod: id }
      )
    }
    const context =
      (typeof node.type === 'string'
        ? contextsBySuite.get(node.type)
        : undefined) ?? deepClone(didDocument['@context'])
    const result = deepClone(node)
    result.id = id
    return (
      context === undefined ? result : { '@context': context, ...result }
    ) as IPublicKey
  }

  /**
   * Returns the public verification method for a purpose from a DID document
   * returned by this driver (whose references are absolute), without
   * `@context`.
   *
   * @param options {object}
   * @param options.didDocument {IDIDDocument}
   * @param options.purpose {string}
   *
   * @returns {IPublicKey}
   */
  publicMethodFor({
    didDocument,
    purpose
  }: { didDocument?: IDIDDocument; purpose?: string } = {}): IPublicKey {
    if (!didDocument) {
      throw new TypeError('The "didDocument" parameter is required.')
    }
    if (!purpose) {
      throw new TypeError('The "purpose" parameter is required.')
    }
    const method = findVerificationMethod({ doc: didDocument, purpose })
    if (!method) {
      throw new Error(`No verification method found for purpose "${purpose}"`)
    }
    return method as IPublicKey
  }

  /**
   * Resolves a short form through the long form store: a missing store or a
   * value that is not a non-empty string is `notFound`; a store that throws,
   * or returns a string that is not a long form, is `internalError`; a stored
   * long form whose own short form differs from the requested one is
   * `invalidDid`. Does not write.
   */
  async _resolveShortForm(shortForm: string): Promise<IDIDDocument> {
    const notFound = (): never => {
      throw resolutionError({
        code: 'notFound',
        message: `Long form for "${shortForm}" has not been seen; a short form resolves only after its long form.`
      })
    }
    if (!this.longFormStore) {
      return notFound()
    }
    let stored: unknown
    try {
      stored = await this.longFormStore.get(shortForm)
    } catch (cause) {
      throw resolutionError({
        code: 'internalError',
        message: `Long form store lookup failed for "${shortForm}".`,
        cause
      })
    }
    if (typeof stored !== 'string' || stored.length === 0) {
      return notFound()
    }
    if (!isLongForm(stored)) {
      throw resolutionError({
        code: 'internalError',
        message: `Long form store returned a value for "${shortForm}" that is not a did:peer numalgo 4 long form.`
      })
    }
    if (longToShort({ did: stored }) !== shortForm) {
      throw resolutionError({
        code: 'invalidDid',
        message: `Stored long form for "${shortForm}" belongs to a different DID.`
      })
    }
    return resolveShortForm({ longFormDid: stored })
  }

  /**
   * Checks that a live pair's public key equals the input document's method
   * `#${fragment}` before the pair is bound to it. A method carrying
   * `publicKeyMultibase` is compared directly. Any other serialization (a 2018
   * suite's `publicKeyBase58`, a JSON Web Key's `publicKeyJwk`) is rebuilt
   * through the pair's own registered suite and compared by fingerprint, so
   * the suite decides which serializations it can read.
   */
  async _assertPairMatchesMethod({
    inputDocument,
    fragment,
    pair
  }: {
    inputDocument: InputDocument
    fragment: string
    pair: AbstractKeyPair
  }): Promise<void> {
    const id = `#${fragment}`
    const method = findResource({
      document: inputDocument,
      id,
      properties: METHOD_PROPERTIES
    })
    if (!method) {
      throw new TypeError(
        `"keyPairs" names fragment "${fragment}" but the input document has no method with id "${id}".`
      )
    }
    const mismatch = (cause?: unknown): TypeError =>
      new TypeError(
        `"keyPairs" pair for fragment "${fragment}" does not match the public key of method "${id}".`,
        { cause }
      )
    const pairMultibase = this._publicKeyMultibaseOf(pair)
    if (typeof method.publicKeyMultibase === 'string') {
      if (method.publicKeyMultibase !== pairMultibase) {
        throw mismatch()
      }
      return
    }
    const registered = this._allowedKeyTypes.get(pairMultibase.slice(0, 4))
    if (!registered) {
      throw new Error(
        `Cannot compare method "${id}" with the pair for fragment "${fragment}": no key suite is registered for header "${pairMultibase.slice(0, 4)}".`
      )
    }
    let rebuilt: AbstractKeyPair
    try {
      rebuilt = await registered.fromMultibase(
        method as unknown as { publicKeyMultibase: string }
      )
    } catch (cause) {
      throw mismatch(cause)
    }
    if (this._publicKeyMultibaseOf(rebuilt) !== pairMultibase) {
      throw mismatch()
    }
  }

  /**
   * Returns a live pair's public key as a multibase Multikey string: its
   * `publicKeyMultibase`, or its `fingerprint()` for a suite that serializes
   * the public key another way.
   */
  _publicKeyMultibaseOf(pair: AbstractKeyPair): string {
    const live = pair as unknown as { publicKeyMultibase?: unknown }
    if (typeof live.publicKeyMultibase === 'string') {
      return live.publicKeyMultibase
    }
    if (typeof pair.fingerprint === 'function') {
      return pair.fingerprint()
    }
    throw new TypeError(
      'A "keyPairs" pair must expose "publicKeyMultibase" or "fingerprint()".'
    )
  }

  /**
   * Derives an X25519 key agreement pair from a live Ed25519 pair when its
   * suite was registered with `enableEncryptionKeyDerivation`; otherwise
   * returns `undefined`.
   */
  _deriveKeyAgreementKey(
    verificationPair: AbstractKeyPair
  ): AbstractKeyPair | undefined {
    const live = verificationPair as unknown as {
      publicKeyMultibase?: string
      privateKeyMultibase?: string
      controller?: string
    }
    const publicKeyMultibase = live.publicKeyMultibase
    if (!publicKeyMultibase?.startsWith(ED25519_MULTIKEY_HEADER)) {
      return undefined
    }
    const registered = this._allowedKeyTypes.get(publicKeyMultibase.slice(0, 4))
    if (!registered?.enableEncryptionKeyDerivation) {
      return undefined
    }
    return X25519KeyAgreementKey2020.fromEd25519({
      controller: live.controller,
      publicKeyMultibase,
      privateKeyMultibase: live.privateKeyMultibase
    }) as unknown as AbstractKeyPair
  }

  /**
   * Generates a key pair from the selected or sole registered suite.
   */
  async _generateKeyPair({
    seed,
    keyType
  }: {
    seed?: string | Uint8Array
    keyType?: KeyPairClass | string
  } = {}): Promise<AbstractKeyPair> {
    let header: string | undefined
    if (keyType) {
      header = typeof keyType === 'string' ? keyType : keyType.multibaseHeader
    } else if (this._allowedKeyTypes.size === 1) {
      ;[header] = this._allowedKeyTypes.keys()
    } else if (this._allowedKeyTypes.size === 0) {
      throw new Error(
        'No key suite registered; call "use({keyPairClass})" or pass a ' +
          '"verificationKeyPair".'
      )
    } else {
      throw new Error(
        'Multiple key suites registered; specify which via "keyType" or pass ' +
          'a "verificationKeyPair".'
      )
    }
    const registered = this._allowedKeyTypes.get(header!)
    if (!registered?.generate) {
      throw new Error(
        `Registered suite "${header}" cannot generate keys; register it via ` +
          '"use({keyPairClass})".'
      )
    }
    const seedBytes = seed === undefined ? undefined : decodeSeed(seed)
    return registered.generate({ seed: seedBytes })
  }

  /**
   * Returns a live key pair for a live instance or a plain public key
   * description (rebuilt through the registered suite for its header).
   */
  async _toKeyPair(
    description: AbstractKeyPair | IKeyPair | IPublicKey
  ): Promise<AbstractKeyPair> {
    const candidate = description as unknown as Record<string, unknown>
    if (typeof candidate?.export === 'function') {
      return description as AbstractKeyPair
    }
    const publicKeyMultibase = candidate?.publicKeyMultibase
    if (typeof publicKeyMultibase !== 'string' || !publicKeyMultibase) {
      throw new TypeError(
        '"publicKeyMultibase" is required to rebuild a key pair.'
      )
    }
    const header = publicKeyMultibase.slice(0, 4)
    const registered = this._allowedKeyTypes.get(header)
    if (!registered) {
      throw new Error(
        `Unsupported multibase header "${header}". Register the suite via ` +
          '"use()".'
      )
    }
    return registered.fromMultibase({ publicKeyMultibase })
  }
}

/**
 * Factory matching the `.driver()` API of the other did-io drivers.
 *
 * @param [options] {DidPeerDriverOptions}
 *
 * @returns {DidPeerDriver}
 */
export function driver(options: DidPeerDriverOptions = {}): DidPeerDriver {
  return new DidPeerDriver(options)
}
