# 0001: No canonicalization of the input document

- Status: accepted
- Date: 2026-11-05
- Driving work: the first release of the did:peer numalgo 4 driver.
- Affects: this repo's `src/numalgo4.ts` and `src/inputDocument.ts`, and
  consumers that derive did:peer DIDs from an input document.

## Context

A numalgo 4 DID is derived from an input document. The long form embeds the
encoded document. The short form is a hash of that encoded string.

The spec says to JSON-stringify the document without whitespace. It prescribes
no canonicalization. The hash covers whatever bytes the creator produced, so
key order and formatting are preserved and verified as given. Decoding never
re-serializes the document.

Resolution is unaffected by serialization differences, because the hash is
over the bytes already in the DID. Only independent re-derivation of the same
DID from the same document can differ between implementations.

## Decision

The library serializes the input document with `JSON.stringify` and no
canonicalization step. Key order is the order the object holds. Non-ASCII
characters are emitted raw. `decode` verifies the hash over the encoded
string as it appears in the DID and never re-serializes.

The README records the interop note. Python's `json.dumps` escapes non-ASCII
text by default, so the same input document with non-ASCII text yields a
different long form there. All published test vectors are ASCII.

## Rejected Alternatives

- Canonicalize the input document (JCS) before hashing. The spec does not do
  it and the reference implementations do not do it. The library would produce
  different DIDs from every other implementation for the same input. This
  rejection is do-not-reopen.
- Escape non-ASCII characters to match Python. The spec text says to
  stringify without whitespace and says nothing about escaping. Matching one
  reference implementation's default is not a spec requirement.

## Consequences

- The library is byte-compatible with the spec text and with other
  implementations for ASCII documents.
- A document with non-ASCII text, integer-like keys or floats can yield a
  different DID from another implementation. JavaScript emits integer-like
  keys first in ascending order. Python and JavaScript also print some floats
  differently.
- Duplicate JSON keys parse last-wins in JavaScript and Python. A first-wins
  parser elsewhere would read a different document under the same DID.
- Resolution of a DID created elsewhere is unaffected.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The peer DID method spec adds a canonicalization or serialization rule for
   numalgo 4.
2. The Python reference or a majority of published implementations change
   their serialization, so that the same input document yields the same DID
   across them.
3. A consumer reports a real interop failure from independent re-derivation
   that the README note does not cover.

If revisited, treat a new rule as a new numalgo profile. Do not change how
existing DIDs are encoded or verified.
