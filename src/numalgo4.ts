/**
 * The pure did:peer numalgo 4 codec: encode an input document into a long or
 * short form, decode a long form back into its input document (verifying the
 * hash), and contextualize a decoded document into a DID document. Everything
 * here is synchronous, does no I/O and imports no key suite. References stay
 * relative, exactly as the spec and the reference implementations leave them;
 * the driver performs reference resolution on top of this output.
 */
import { base58 } from '@scure/base'
import { sha256 } from '@noble/hashes/sha2.js'
import { concatBytes } from '@noble/hashes/utils.js'
import {
  DIDResolutionError,
  type IDIDDocument,
  type IDIDResolutionErrorCode
} from '@interop/data-integrity-core'
import { deepClone } from '@interop/did-io'
import {
  MAX_LONG_FORM_LENGTH,
  MULTIBASE_BASE58BTC_PREFIX,
  MULTICODEC_JSON_HEADER,
  MULTIHASH_SHA2_256_HEADER,
  NUMALGO_4_PREFIX
} from './constants.js'
import { METHOD_PROPERTIES, isPlainObject } from './resources.js'
import type { InputDocument } from './types.js'

export { MAX_LONG_FORM_LENGTH } from './constants.js'

/**
 * Matches a long form: a fixed `zQm` prefix (every hash is a base58btc
 * sha2-256 multihash), 44 more base58 characters, then the encoded document,
 * at least 6 base58 characters (what `{}` encodes to). Bitcoin alphabet.
 */
export const LONG_FORM_PATTERN =
  /^did:peer:4zQm[1-9A-HJ-NP-Za-km-z]{44}:z[1-9A-HJ-NP-Za-km-z]{6,}$/

/**
 * Matches a short form: `did:peer:4` followed by the 46-character hash.
 */
export const SHORT_FORM_PATTERN = /^did:peer:4zQm[1-9A-HJ-NP-Za-km-z]{44}$/

const PROBLEM_TYPES: Record<string, { type: string; title: string }> = {
  invalidDid: {
    type: 'https://www.w3.org/ns/did#INVALID_DID',
    title: 'The DID is invalid.'
  },
  invalidDidUrl: {
    type: 'https://www.w3.org/ns/did#INVALID_DID_URL',
    title: 'The DID URL is invalid.'
  },
  methodNotSupported: {
    type: 'https://www.w3.org/ns/did#METHOD_NOT_SUPPORTED',
    title: 'The DID method is not supported.'
  },
  notFound: {
    type: 'https://www.w3.org/ns/did#NOT_FOUND',
    title: 'The DID document was not found.'
  },
  internalError: {
    type: 'https://www.w3.org/ns/did#INTERNAL_ERROR',
    title: 'An internal error occurred during resolution.'
  }
}

/**
 * Builds a `DIDResolutionError` with the spec problem details for its code.
 * The codec and the driver throw this directly (no private error class), so
 * `CachedResolver.resolveDID()` produces the right envelope without a
 * translation layer.
 *
 * @param options {object}
 * @param options.code {IDIDResolutionErrorCode}
 * @param options.message {string}
 * @param [options.cause] {unknown}
 *
 * @returns {DIDResolutionError}
 */
export function resolutionError({
  code,
  message,
  cause
}: {
  code: IDIDResolutionErrorCode
  message: string
  cause?: unknown
}): DIDResolutionError {
  const problem = PROBLEM_TYPES[code]
  return new DIDResolutionError(message, {
    code,
    problemDetails: problem ? { ...problem, detail: message } : undefined,
    cause
  })
}

function invalidDid(message: string, cause?: unknown): DIDResolutionError {
  return resolutionError({ code: 'invalidDid', message, cause })
}

/**
 * Produces the encoded document: the input document JSON-stringified without
 * whitespace, UTF-8 encoded, prefixed with the multicodec `json` header and
 * multibase base58btc encoded.
 */
function encodeDocument(inputDocument: InputDocument): string {
  const bytes = new TextEncoder().encode(JSON.stringify(inputDocument))
  try {
    return (
      MULTIBASE_BASE58BTC_PREFIX +
      base58.encode(concatBytes(MULTICODEC_JSON_HEADER, bytes))
    )
  } catch (cause) {
    // @scure/base refuses base58 inputs over 2048 bytes (quadratic encoder).
    throw new Error(
      `Input document is too large to base58-encode (${bytes.length} bytes of JSON).`,
      { cause }
    )
  }
}

/**
 * Hashes an encoded document string (including its leading `z`) with
 * sha2-256 and returns the base58btc multibase of the sha2-256 multihash.
 */
function hashEncodedDocument(encodedDocument: string): string {
  const digest = sha256(new TextEncoder().encode(encodedDocument))
  return (
    MULTIBASE_BASE58BTC_PREFIX +
    base58.encode(concatBytes(MULTIHASH_SHA2_256_HEADER, digest))
  )
}

/**
 * Encodes an input document into its long form. Does not validate; validation
 * is the driver's job at `generate()` time.
 *
 * @param options {object}
 * @param options.inputDocument {InputDocument}
 *
 * @returns {string} The long form `did:peer:4{hash}:{encoded document}`.
 */
export function encodeLongForm({
  inputDocument
}: {
  inputDocument: InputDocument
}): string {
  const encodedDocument = encodeDocument(inputDocument)
  const hash = hashEncodedDocument(encodedDocument)
  return `${NUMALGO_4_PREFIX}${hash}:${encodedDocument}`
}

/**
 * Encodes an input document into its short form. Does not validate.
 *
 * @param options {object}
 * @param options.inputDocument {InputDocument}
 *
 * @returns {string} The short form `did:peer:4{hash}`.
 */
export function encodeShortForm({
  inputDocument
}: {
  inputDocument: InputDocument
}): string {
  return `${NUMALGO_4_PREFIX}${hashEncodedDocument(encodeDocument(inputDocument))}`
}

/**
 * Whether a string starts with the numalgo 4 prefix `did:peer:4`.
 *
 * @param did {string}
 *
 * @returns {boolean}
 */
export function isDidPeer4(did: string): boolean {
  return typeof did === 'string' && did.startsWith(NUMALGO_4_PREFIX)
}

/**
 * Whether a string matches the long form grammar. Does not verify the hash.
 *
 * @param did {string}
 *
 * @returns {boolean}
 */
export function isLongForm(did: string): boolean {
  return typeof did === 'string' && LONG_FORM_PATTERN.test(did)
}

/**
 * Whether a string matches the short form grammar.
 *
 * @param did {string}
 *
 * @returns {boolean}
 */
export function isShortForm(did: string): boolean {
  return typeof did === 'string' && SHORT_FORM_PATTERN.test(did)
}

/**
 * Returns the short form of a long form by string surgery (regex guarded). It
 * does not verify the hash; callers that need that call `decode` first.
 *
 * @param options {object}
 * @param options.did {string} - A long form.
 *
 * @throws {DIDResolutionError} `invalidDid` if `did` is not a long form.
 *
 * @returns {string} The short form.
 */
export function longToShort({ did }: { did: string }): string {
  if (!isLongForm(did)) {
    throw invalidDid(`Not a did:peer numalgo 4 long form: "${String(did)}".`)
  }
  return did.slice(0, did.lastIndexOf(':'))
}

/**
 * Decodes a long form into its input document, verifying the hash over the
 * encoded document string exactly as present in the DID. Rejects anything that
 * is not a numalgo 4 long form, a long form over `MAX_LONG_FORM_LENGTH`, a
 * hash mismatch, a bad multicodec prefix, invalid UTF-8 or JSON, and a payload
 * that is not a plain object. Returns a freshly parsed document on every call.
 *
 * @param options {object}
 * @param options.did {string} - A long form.
 *
 * @throws {TypeError} If `did` is not a string.
 * @throws {DIDResolutionError} With code `invalidDid` for every other failure.
 *
 * @returns {InputDocument} The input document, relative references intact.
 */
export function decode({ did }: { did: string }): InputDocument {
  if (typeof did !== 'string') {
    throw new TypeError('"did" must be a string.')
  }
  if (!isDidPeer4(did)) {
    throw invalidDid(`Not a did:peer numalgo 4 DID: "${did}".`)
  }
  if (did.length > MAX_LONG_FORM_LENGTH) {
    throw invalidDid(
      `Long form exceeds the maximum length of ${MAX_LONG_FORM_LENGTH} characters.`
    )
  }
  if (isShortForm(did)) {
    throw invalidDid(
      `Cannot decode a short form; the document is not recoverable from "${did}".`
    )
  }
  if (!isLongForm(did)) {
    throw invalidDid(`Malformed did:peer numalgo 4 long form: "${did}".`)
  }
  const separator = did.lastIndexOf(':')
  const hash = did.slice(NUMALGO_4_PREFIX.length, separator)
  const encodedDocument = did.slice(separator + 1)
  if (hashEncodedDocument(encodedDocument) !== hash) {
    throw invalidDid(
      'Long form hash does not match its encoded document; the DID is corrupt or tampered.'
    )
  }
  let bytes: Uint8Array
  try {
    bytes = base58.decode(encodedDocument.slice(1))
  } catch (cause) {
    throw invalidDid('Encoded document is not valid base58btc.', cause)
  }
  if (
    bytes.length < MULTICODEC_JSON_HEADER.length ||
    bytes[0] !== MULTICODEC_JSON_HEADER[0] ||
    bytes[1] !== MULTICODEC_JSON_HEADER[1]
  ) {
    throw invalidDid(
      'Encoded document does not carry the multicodec json prefix.'
    )
  }
  let parsed: unknown
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(
      bytes.subarray(MULTICODEC_JSON_HEADER.length)
    )
    parsed = JSON.parse(text)
  } catch (cause) {
    throw invalidDid('Encoded document is not valid UTF-8 JSON.', cause)
  }
  if (!isPlainObject(parsed)) {
    throw invalidDid('Encoded document is not a JSON object.')
  }
  return parsed
}

/**
 * Contextualizes a decoded input document: deep-copies it, sets the root `id`,
 * appends `alsoKnownAs`, and sets `controller` on every verification method
 * (listed or embedded) that has no own `controller` property. Relative
 * references are left relative. Total over hash-valid input: a shape it cannot
 * handle is `invalidDid` rather than a bare `TypeError`.
 */
function contextualize({
  inputDocument,
  did,
  alsoKnownAs
}: {
  inputDocument: InputDocument
  did: string
  alsoKnownAs: string
}): IDIDDocument {
  const doc = deepClone(inputDocument)
  doc.id = did
  if (!Object.hasOwn(doc, 'alsoKnownAs')) {
    doc.alsoKnownAs = [alsoKnownAs]
  } else if (Array.isArray(doc.alsoKnownAs)) {
    doc.alsoKnownAs.push(alsoKnownAs)
  } else {
    throw invalidDid('"alsoKnownAs" in the encoded document is not an array.')
  }
  for (const property of METHOD_PROPERTIES) {
    if (!Object.hasOwn(doc, property)) {
      continue
    }
    const entries = doc[property]
    if (!Array.isArray(entries)) {
      throw invalidDid(`"${property}" in the encoded document is not an array.`)
    }
    for (const entry of entries) {
      if (typeof entry === 'string') {
        continue
      }
      if (!isPlainObject(entry)) {
        throw invalidDid(
          `"${property}" in the encoded document holds an entry that is neither a reference nor a verification method.`
        )
      }
      if (!Object.hasOwn(entry, 'controller')) {
        entry.controller = did
      }
    }
  }
  return doc as unknown as IDIDDocument
}

/**
 * Resolves a long form to its DID document: `decode` (regex, length and hash
 * checks) followed by contextualization with the long form as `id` and the
 * short form appended to `alsoKnownAs`. References stay relative.
 *
 * @param options {object}
 * @param options.did {string} - A long form.
 *
 * @returns {IDIDDocument}
 */
export function resolveLongForm({ did }: { did: string }): IDIDDocument {
  const inputDocument = decode({ did })
  return contextualize({
    inputDocument,
    did,
    alsoKnownAs: longToShort({ did })
  })
}

/**
 * Resolves a short form from its long form: decodes the long form (so the
 * regex and hash checks run), then contextualizes with the short form as `id`
 * and the long form appended to `alsoKnownAs`. References stay relative.
 *
 * @param options {object}
 * @param options.longFormDid {string} - The long form previously seen.
 *
 * @returns {IDIDDocument}
 */
export function resolveShortForm({
  longFormDid
}: {
  longFormDid: string
}): IDIDDocument {
  const inputDocument = decode({ did: longFormDid })
  return contextualize({
    inputDocument,
    did: longToShort({ did: longFormDid }),
    alsoKnownAs: longFormDid
  })
}
