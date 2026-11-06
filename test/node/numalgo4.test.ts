import { describe, it, expect } from 'vitest'
import { base58 } from '@scure/base'
import { sha256 } from '@noble/hashes/sha2.js'
import {
  decode,
  encodeLongForm,
  encodeShortForm,
  isDidPeer4,
  isLongForm,
  isShortForm,
  longToShort,
  resolveLongForm,
  resolveShortForm,
  LONG_FORM_PATTERN,
  MAX_LONG_FORM_LENGTH,
  SHORT_FORM_PATTERN
} from '../../src/codec.js'
import vectors from '../fixtures/test-vectors.json' with { type: 'json' }

type Vector = {
  name: string
  inputDocument: Record<string, unknown>
  longForm: string
  shortForm: string
}

const RELATIONSHIPS = [
  'authentication',
  'assertionMethod',
  'capabilityDelegation',
  'capabilityInvocation',
  'keyAgreement'
]

function methodsOf(doc: Record<string, unknown>): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = []
  for (const property of ['verificationMethod', ...RELATIONSHIPS]) {
    const entries = doc[property]
    if (Array.isArray(entries)) {
      out.push(...entries.filter(entry => typeof entry === 'object'))
    }
  }
  return out
}

function expectInvalidDid(fn: () => unknown, messagePart?: string): void {
  let caught: unknown
  try {
    fn()
  } catch (err) {
    caught = err
  }
  expect(caught).toBeInstanceOf(Error)
  const error = caught as Error & { code?: string }
  expect(error.name).toBe('DIDResolutionError')
  expect(error.code).toBe('invalidDid')
  expect(error).not.toBeInstanceOf(TypeError)
  if (messagePart) {
    expect(error.message).toContain(messagePart)
  }
}

/**
 * Builds a hash-valid long form for an arbitrary JSON payload (the codec's
 * encoders accept only objects at the type level, so hostile payloads go
 * through this).
 */
function longFormOf(payload: unknown): string {
  return encodeLongForm({ inputDocument: payload as Record<string, unknown> })
}

describe('numalgo 4 codec', () => {
  describe.each(vectors as Vector[])('vector $name', vector => {
    const { inputDocument, longForm, shortForm } = vector

    it('encodes the long form', () => {
      expect(encodeLongForm({ inputDocument })).toBe(longForm)
    })

    it('encodes the short form', () => {
      expect(encodeShortForm({ inputDocument })).toBe(shortForm)
    })

    it('matches the regexes', () => {
      expect(LONG_FORM_PATTERN.test(longForm)).toBe(true)
      expect(SHORT_FORM_PATTERN.test(shortForm)).toBe(true)
      expect(isLongForm(longForm)).toBe(true)
      expect(isShortForm(shortForm)).toBe(true)
      expect(isShortForm(longForm)).toBe(false)
      expect(isLongForm(shortForm)).toBe(false)
      expect(isDidPeer4(longForm)).toBe(true)
    })

    it('derives the short form from the long form', () => {
      expect(longToShort({ did: longForm })).toBe(shortForm)
    })

    it('decodes back to the input document', () => {
      expect(decode({ did: longForm })).toEqual(inputDocument)
    })

    it('hashes the encoded document string as present in the DID', () => {
      const encoded = longForm.slice(longForm.lastIndexOf(':') + 1)
      const hash = longForm.slice(
        'did:peer:4'.length,
        longForm.lastIndexOf(':')
      )
      expect(encoded.startsWith('z')).toBe(true)
      expect(hash.startsWith('zQm')).toBe(true)
      const bytes = base58.decode(hash.slice(1))
      expect([bytes[0], bytes[1]]).toEqual([0x12, 0x20])
      expect(bytes.length).toBe(34)
    })

    it('resolves the long form', () => {
      const resolved = resolveLongForm({ did: longForm }) as unknown as Record<
        string,
        unknown
      >
      expect(resolved.id).toBe(longForm)
      expect((resolved.alsoKnownAs as string[]).at(-1)).toBe(shortForm)
      const inputMethods = methodsOf(inputDocument)
      const resolvedMethods = methodsOf(resolved)
      expect(resolvedMethods.length).toBe(inputMethods.length)
      resolvedMethods.forEach((method, index) => {
        const original = inputMethods[index]!
        if (Object.hasOwn(original, 'controller')) {
          expect(method.controller).toEqual(original.controller)
        } else {
          expect(method.controller).toBe(longForm)
        }
        expect(method.id).toBe(original.id)
      })
      // every other property is untouched (incl. publicKey and service)
      for (const [key, value] of Object.entries(inputDocument)) {
        if (
          key === 'alsoKnownAs' ||
          key === 'verificationMethod' ||
          RELATIONSHIPS.includes(key)
        ) {
          continue
        }
        expect(resolved[key]).toEqual(value)
      }
    })

    it('resolves the short form', () => {
      const resolved = resolveShortForm({
        longFormDid: longForm
      }) as unknown as Record<string, unknown>
      expect(resolved.id).toBe(shortForm)
      expect((resolved.alsoKnownAs as string[]).at(-1)).toBe(longForm)
      const inputMethods = methodsOf(inputDocument)
      methodsOf(resolved).forEach((method, index) => {
        if (!Object.hasOwn(inputMethods[index]!, 'controller')) {
          expect(method.controller).toBe(shortForm)
        }
      })
    })
  })

  it('leaves the legacy publicKey array uncontextualized (vector examples/3.json)', () => {
    const vector = (vectors as Vector[]).find(
      v => v.name === 'examples/3.json'
    )!
    const resolved = resolveLongForm({
      did: vector.longForm
    }) as unknown as Record<string, unknown>
    expect(resolved.publicKey).toEqual(vector.inputDocument.publicKey)
    const [embedded] = resolved.keyAgreement as Record<string, unknown>[]
    expect(embedded!.controller).toBe(vector.longForm)
  })

  describe('decode rejections', () => {
    const vector = (vectors as Vector[])[1]!
    const { longForm, shortForm } = vector

    it('rejects a non-string with a TypeError', () => {
      expect(() => decode({ did: 5 as unknown as string })).toThrow(TypeError)
    })

    it('rejects a tampered hash', () => {
      const index = 'did:peer:4zQm'.length + 3
      const flipped = longForm[index] === 'a' ? 'b' : 'a'
      const tampered =
        longForm.slice(0, index) + flipped + longForm.slice(index + 1)
      expectInvalidDid(() => decode({ did: tampered }), 'hash does not match')
    })

    it('rejects a tampered document', () => {
      const index = longForm.length - 5
      const flipped = longForm[index] === 'a' ? 'b' : 'a'
      const tampered =
        longForm.slice(0, index) + flipped + longForm.slice(index + 1)
      expectInvalidDid(() => decode({ did: tampered }), 'hash does not match')
    })

    it('rejects a short form', () => {
      expectInvalidDid(
        () => decode({ did: shortForm }),
        'Cannot decode a short form'
      )
    })

    it('rejects other numalgos and non-did:peer strings', () => {
      expectInvalidDid(() =>
        decode({
          did: 'did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc'
        })
      )
      expectInvalidDid(() =>
        decode({
          did: 'did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V'
        })
      )
      expectInvalidDid(() =>
        decode({
          did: 'did:key:z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V'
        })
      )
      expect(isLongForm('did:peer:2.Ez6LS')).toBe(false)
      expect(isShortForm('did:peer:0z6Mk')).toBe(false)
    })

    it('rejects a wrong multibase prefix on the encoded document', () => {
      const separator = longForm.lastIndexOf(':')
      const wrong =
        longForm.slice(0, separator + 1) + 'm' + longForm.slice(separator + 2)
      expectInvalidDid(() => decode({ did: wrong }))
    })

    it('rejects a wrong multicodec prefix', () => {
      const bytes = new TextEncoder().encode(JSON.stringify({ a: 1 }))
      const prefixed = new Uint8Array([0x80, 0x05, ...bytes])
      const encoded = 'z' + base58.encode(prefixed)
      // build a DID whose hash is valid for this encoded document
      const hashed = encodeLongForm({ inputDocument: { a: 1 } })
      const valid = decode({ did: hashed })
      expect(valid).toEqual({ a: 1 })
      // compute a correct hash for the bad payload via the public encoder's
      // shape: splice our encoded doc into the long form and recompute hash
      const digest = sha256(new TextEncoder().encode(encoded))
      const hash = 'z' + base58.encode(new Uint8Array([0x12, 0x20, ...digest]))
      expectInvalidDid(
        () => decode({ did: `did:peer:4${hash}:${encoded}` }),
        'multicodec json prefix'
      )
    })

    it('rejects a long form over MAX_LONG_FORM_LENGTH before decoding', () => {
      // Syntactically valid, hash-invalid, one character over the limit: the
      // length check must fire before the hash check does.
      const prefix = longForm.slice(0, longForm.lastIndexOf(':') + 2)
      const overLimit =
        prefix + 'a'.repeat(MAX_LONG_FORM_LENGTH + 1 - prefix.length)
      expect(overLimit.length).toBe(MAX_LONG_FORM_LENGTH + 1)
      expect(isLongForm(overLimit)).toBe(true)
      expectInvalidDid(() => decode({ did: overLimit }), 'maximum length')
    })

    it('rejects hash-valid payloads that are not plain objects', () => {
      for (const payload of [null, [], 'str', 5, [{ id: 1 }]]) {
        expectInvalidDid(() => resolveLongForm({ did: longFormOf(payload) }))
      }
    })

    it('boundary: {} encodes to six characters and passes; 0 fails the regex', () => {
      const empty = encodeLongForm({ inputDocument: {} })
      expect(empty.slice(empty.lastIndexOf(':') + 2).length).toBe(6)
      expect(decode({ did: empty })).toEqual({})
      const zero = longFormOf(0)
      expect(isLongForm(zero)).toBe(false)
      expectInvalidDid(() => decode({ did: zero }))
    })

    it('longToShort is regex guarded', () => {
      expectInvalidDid(() => longToShort({ did: shortForm }))
      expectInvalidDid(() => longToShort({ did: 'did:web:example.com' }))
    })
  })

  describe('contextualization', () => {
    const vector = (vectors as Vector[]).find(
      v => v.name === 'examples/2.json'
    )!

    it('does not mutate the caller input across long and short resolution', () => {
      const inputDocument = decode({ did: vector.longForm })
      const snapshot = JSON.parse(JSON.stringify(inputDocument))
      const long = resolveLongForm({ did: vector.longForm }) as any
      const short = resolveShortForm({ longFormDid: vector.longForm }) as any
      expect(inputDocument).toEqual(snapshot)
      expect(long.authentication[0].controller).toBe(vector.longForm)
      expect(short.authentication[0].controller).toBe(vector.shortForm)
      expect(long.alsoKnownAs).toEqual([vector.shortForm])
      expect(short.alsoKnownAs).toEqual([vector.longForm])
    })

    it('appends to an existing alsoKnownAs', () => {
      const did = longFormOf({
        alsoKnownAs: ['did:example:other'],
        hello: 'world'
      })
      const resolved = resolveLongForm({ did }) as any
      expect(resolved.alsoKnownAs).toEqual([
        'did:example:other',
        longToShort({ did })
      ])
    })

    it('keeps an existing controller, including null', () => {
      const did = longFormOf({
        authentication: [
          { id: '#a', type: 'Multikey', controller: 'did:example:other' },
          { id: '#b', type: 'Multikey', controller: null }
        ]
      })
      const resolved = resolveLongForm({ did }) as any
      expect(resolved.authentication[0].controller).toBe('did:example:other')
      expect(resolved.authentication[1].controller).toBeNull()
    })

    it('overwrites a root id present in the input', () => {
      const did = longFormOf({ id: 'did:example:bogus', hello: 'world' })
      expect((resolveLongForm({ did }) as any).id).toBe(did)
    })

    it('rejects hostile hash-valid shapes with invalidDid rather than TypeError', () => {
      const shapes: unknown[] = [
        { alsoKnownAs: 'str' },
        { alsoKnownAs: null },
        { alsoKnownAs: {} },
        { verificationMethod: 'str' },
        { authentication: [null] },
        { authentication: [5] },
        { authentication: [[]] },
        { keyAgreement: { id: '#k' } }
      ]
      for (const shape of shapes) {
        expectInvalidDid(() => resolveLongForm({ did: longFormOf(shape) }))
      }
    })

    it('keeps an own __proto__ key without altering the prototype', () => {
      const encoded = JSON.parse(
        '{"__proto__":{"polluted":true},"hello":"world"}'
      )
      const did = longFormOf(encoded)
      const resolved = resolveLongForm({ did }) as any
      expect(Object.getPrototypeOf(resolved)).toBe(Object.prototype)
      expect(resolved.polluted).toBeUndefined()
      expect(Object.hasOwn(resolved, '__proto__')).toBe(true)
    })
  })
})
