/**
 * Input document helpers: the superficial validation applied on every
 * `generate()` path (never on resolution), and the builder that exports a live
 * key pair into an owner-controlled, relative-id verification method and wires
 * it into the requested relationships.
 */
import type {
  AbstractKeyPair,
  IVerificationMethodEntry
} from '@interop/data-integrity-core'
import { VERIFICATION_RELATIONSHIPS, deepClone } from '@interop/did-io'
import { RESOURCE_PROPERTIES, isPlainObject } from './resources.js'
import type { InputDocument } from './types.js'

/**
 * A relative fragment reference: `#` followed by a non-empty fragment that
 * contains no further `#`.
 */
const RELATIVE_ID_PATTERN = /^#[^#]+$/

/**
 * Validates an input document before encoding. Deliberately superficial, as
 * the Python reference's `validate_input_document`: the document must be a
 * non-empty plain object without a root `id`; `alsoKnownAs`, if present, and
 * each of `verificationMethod`, the five relationships and `service`, if
 * present, must be arrays; every object entry in those arrays must have a
 * relative string `id` (`#fragment`) and a `type`; and resource ids must be
 * unique across all of them. String entries are references and are not
 * checked. Key material is not validated.
 *
 * @param options {object}
 * @param options.inputDocument {InputDocument}
 *
 * @throws {TypeError} Naming the failing path, e.g.
 *   `authentication[1]: resource id must be relative`.
 */
export function validateInputDocument({
  inputDocument
}: {
  inputDocument: InputDocument
}): void {
  if (
    !isPlainObject(inputDocument) ||
    Object.keys(inputDocument).length === 0
  ) {
    throw new TypeError('inputDocument: must be a non-empty object.')
  }
  if (Object.hasOwn(inputDocument, 'id')) {
    throw new TypeError('inputDocument: must not have a root "id".')
  }
  if (
    Object.hasOwn(inputDocument, 'alsoKnownAs') &&
    !Array.isArray(inputDocument.alsoKnownAs)
  ) {
    throw new TypeError('alsoKnownAs: must be an array.')
  }
  const seen = new Map<string, string>()
  for (const property of RESOURCE_PROPERTIES) {
    if (!Object.hasOwn(inputDocument, property)) {
      continue
    }
    const entries = inputDocument[property]
    if (!Array.isArray(entries)) {
      throw new TypeError(`${property}: must be an array.`)
    }
    entries.forEach((entry, index) => {
      if (typeof entry === 'string') {
        return
      }
      const path = `${property}[${index}]`
      if (!isPlainObject(entry)) {
        throw new TypeError(`${path}: resource must be an object.`)
      }
      if (typeof entry.id !== 'string') {
        throw new TypeError(`${path}: resource id must be a string.`)
      }
      if (!RELATIVE_ID_PATTERN.test(entry.id)) {
        throw new TypeError(`${path}: resource id must be relative.`)
      }
      if (typeof entry.type !== 'string' || entry.type.length === 0) {
        throw new TypeError(`${path}: resource must have a type.`)
      }
      const previous = seen.get(entry.id)
      if (previous !== undefined) {
        throw new TypeError(
          `${path}: duplicate resource id "${entry.id}" (also at ${previous}).`
        )
      }
      seen.set(entry.id, path)
    })
  }
}

/**
 * Adds one or more contexts to an input document's `@context`, de-duplicating.
 */
function addContext({
  inputDocument,
  context
}: {
  inputDocument: InputDocument
  context: unknown
}): void {
  const existing = inputDocument['@context']
  let contexts: unknown[]
  if (Array.isArray(existing)) {
    contexts = existing
  } else if (existing === undefined) {
    contexts = []
  } else {
    contexts = [existing]
  }
  for (const ctx of Array.isArray(context) ? context : [context]) {
    if (!contexts.includes(ctx)) {
      contexts.push(ctx)
    }
  }
  inputDocument['@context'] = contexts
}

function assertPurposes(purposes: string[]): void {
  for (const purpose of purposes) {
    if (!VERIFICATION_RELATIONSHIPS.has(purpose)) {
      throw new Error(`Unsupported key purpose: "${purpose}".`)
    }
  }
}

function pushTo({
  inputDocument,
  property,
  value
}: {
  inputDocument: InputDocument
  property: string
  value: unknown
}): void {
  const existing = inputDocument[property]
  if (existing === undefined) {
    inputDocument[property] = [value]
  } else if (Array.isArray(existing)) {
    existing.push(value)
  } else {
    throw new TypeError(`${property}: must be an array.`)
  }
}

/**
 * Lists a method node under `verificationMethod` and references its id from
 * each purpose.
 */
function placeMethod({
  inputDocument,
  node,
  purposes
}: {
  inputDocument: InputDocument
  node: Record<string, unknown>
  purposes: string[]
}): void {
  pushTo({ inputDocument, property: 'verificationMethod', value: node })
  for (const purpose of purposes) {
    pushTo({ inputDocument, property: purpose, value: node.id })
  }
}

/**
 * Exports a live key pair's public node and adds it to an input document as
 * an owner-controlled verification method. The node's `@context` moves into
 * the document's `@context` (de-duplicated); its `id` becomes the relative
 * `#${fragment}`; `controller` and the absolute id a live pair carries are
 * stripped, since the owner DID does not exist until the hash is computed. The
 * node is listed under `verificationMethod` and referenced by id from each
 * purpose.
 *
 * @param options {object}
 * @param options.inputDocument {InputDocument} - Document to mutate.
 * @param options.keyPair {AbstractKeyPair} - A live key pair (with `export()`).
 * @param [options.fragment] {string} - Defaults to the pair's `fingerprint()`.
 * @param [options.purposes] {string[]} - Verification relationships to wire.
 *
 * @returns {Promise<{inputDocument: InputDocument, fragment: string}>}
 */
export async function addVerificationMethod({
  inputDocument,
  keyPair,
  fragment,
  purposes = []
}: {
  inputDocument: InputDocument
  keyPair: AbstractKeyPair
  fragment?: string
  purposes?: string[]
}): Promise<{ inputDocument: InputDocument; fragment: string }> {
  if (typeof keyPair?.export !== 'function') {
    throw new TypeError('"keyPair" must be a live key pair with "export()".')
  }
  assertPurposes(purposes)
  if (fragment === undefined) {
    if (typeof keyPair.fingerprint !== 'function') {
      throw new TypeError(
        'Cannot determine a default fragment; provide a "fragment".'
      )
    }
    fragment = keyPair.fingerprint()
  }
  const node = (await keyPair.export({
    publicKey: true,
    includeContext: true
  } as object)) as Record<string, unknown>
  const context = node['@context']
  delete node['@context']
  delete node.controller
  node.id = `#${fragment}`
  if (context !== undefined) {
    addContext({ inputDocument, context })
  }
  placeMethod({ inputDocument, node, purposes })
  return { inputDocument, fragment }
}

/**
 * Adds a third-party-controlled method to an input document, placed verbatim:
 * a string is a reference appended to each purpose; an object (carrying its
 * own `id`, `type`, `controller` and key material) is listed under
 * `verificationMethod` and referenced from each purpose. No live pair is bound
 * for it.
 *
 * @param options {object}
 * @param options.inputDocument {InputDocument} - Document to mutate.
 * @param options.entry {IVerificationMethodEntry}
 * @param options.purposes {string[]}
 */
export function addThirdPartyMethod({
  inputDocument,
  entry,
  purposes
}: {
  inputDocument: InputDocument
  entry: IVerificationMethodEntry
  purposes: string[]
}): void {
  assertPurposes(purposes)
  if (typeof entry === 'string') {
    for (const purpose of purposes) {
      pushTo({ inputDocument, property: purpose, value: entry })
    }
    return
  }
  if (!isPlainObject(entry) || typeof entry.id !== 'string') {
    throw new TypeError(
      'A "verificationMethods" entry must be a key pair entry, a DID URL string, or a verification method object with a string "id".'
    )
  }
  placeMethod({
    inputDocument,
    node: deepClone(entry) as Record<string, unknown>,
    purposes
  })
}
