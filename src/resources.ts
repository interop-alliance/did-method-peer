/**
 * Shared helpers for walking the resource arrays of an input or DID document:
 * `verificationMethod`, the five verification relationships and `service`.
 * Imported by the codec, the input document helpers and the driver alike, so
 * the plain-object test and the property lists exist once.
 */
import { VERIFICATION_RELATIONSHIPS } from '@interop/did-io'

/**
 * The properties whose entries are verification methods or references to
 * them.
 */
export const METHOD_PROPERTIES = [
  'verificationMethod',
  ...VERIFICATION_RELATIONSHIPS
]

/**
 * Every property whose entries carry a resource id.
 */
export const RESOURCE_PROPERTIES = [...METHOD_PROPERTIES, 'service']

export function isPlainObject(
  value: unknown
): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Finds the object entry with the given `id` across `properties`, searched in
 * order. String entries are references and are skipped.
 *
 * @param options {object}
 * @param options.document {Record<string, unknown>}
 * @param options.id {string}
 * @param [options.properties] {string[]} - Defaults to `RESOURCE_PROPERTIES`.
 *
 * @returns {Record<string, unknown> | undefined}
 */
export function findResource({
  document,
  id,
  properties = RESOURCE_PROPERTIES
}: {
  document: Record<string, unknown>
  id: string
  properties?: string[]
}): Record<string, unknown> | undefined {
  for (const property of properties) {
    const entries = document[property]
    if (!Array.isArray(entries)) {
      continue
    }
    const match = entries.find(entry => isPlainObject(entry) && entry.id === id)
    if (match) {
      return match
    }
  }
  return undefined
}
