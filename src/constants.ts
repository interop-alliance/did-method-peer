/**
 * Shared constants for the did:peer numalgo 4 codec and driver: the DID Core
 * context URL, the did:peer prefixes, the two multicodec/multihash headers the
 * codec needs (inlined as byte constants so no varint library is required),
 * the long form length limit, and the default verification relationships for
 * a generated verification key.
 */

export const DID_CONTEXT_URL = 'https://www.w3.org/ns/did/v1'

export const DID_PEER_PREFIX = 'did:peer:'
export const NUMALGO_4_PREFIX = 'did:peer:4'

/**
 * Multicodec `json` code (0x0200) as its two-byte unsigned varint.
 */
export const MULTICODEC_JSON_HEADER = new Uint8Array([0x80, 0x04])

/**
 * Multihash header for sha2-256: code 0x12, digest length 0x20 (32 bytes).
 */
export const MULTIHASH_SHA2_256_HEADER = new Uint8Array([0x12, 0x20])

export const MULTIBASE_BASE58BTC_PREFIX = 'z'

/**
 * Longest long form `decode` accepts, in characters. A long form carries an
 * attacker-chosen document, and base58-decoding plus parsing a multi-megabyte
 * string would block the event loop, so anything longer is rejected before
 * hashing. 4096 characters is roughly four times the largest published vector
 * and matches the longest base58 string `@scure/base` will decode, so the
 * length check, not the base58 decoder, is what rejects an oversized long form.
 */
export const MAX_LONG_FORM_LENGTH = 4096

/**
 * The verification relationships a generated verification key is wired into
 * when no explicit `purposes` are given for it (the same four as
 * `@interop/did-method-key` and `@interop/did-web-resolver`).
 */
export const DEFAULT_PURPOSES = [
  'authentication',
  'assertionMethod',
  'capabilityDelegation',
  'capabilityInvocation'
]
