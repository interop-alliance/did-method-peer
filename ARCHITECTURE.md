# Architecture

The current shape of this library, with the rationale inline: why each part is
shaped the way it is, stated where the shape is described. This file is kept
current in the same change set that alters the shape; it overwrites in place and
records no history. History lives elsewhere: CHANGELOG.md for what landed,
`decisions/` for durable decisions with their rejected alternatives and revisit
criteria, and the archived roadmap for the work items. Reference decision
records from here where the resulting shape is described, instead of re-arguing
them.

Several conventions lean on this file, so keep it accurate and current: the
design gate defines a cross-cutting item as one touching an invariant documented
here, a `touches:` entry names this file as a deliverable in its own right, and
the breaking-release audit checks its statements against the code.

`@interop/did-method-peer` is a `did:peer` numalgo 4 driver for
`@interop/did-io`. It has two halves. A pure codec encodes, decodes, hashes and
contextualizes numalgo 4 DIDs. A driver plugs the codec into did-io's
`CachedResolver` and adds `generate()` and key node lookup.

## Layer map

```
src/index.ts              Public entry point (the `.` export: codec + driver)
src/codec.ts              The `./codec` export: codec names only, no driver
src/DidPeerDriver.ts      DidPeerDriver: did-io DidMethodDriver for did:peer
src/numalgo4.ts           Pure codec: encode/decode/hash/contextualize, regexes
src/inputDocument.ts      Input document building (from key pairs) + validation
src/resources.ts          Resource-array walking shared by codec, helpers, driver
src/constants.ts          Context URLs, multicodec/multihash prefixes, defaults
src/types.ts              Shared types (KeyPairClass, FromMultibase, LongFormStore)
```

There is no `src/declarations.d.ts`. No untyped dependency remains, so the
ambient shim file is not needed.

The export map has two doors. The `.` export serves `src/index.ts`, which
exports the codec and the driver together. The `./codec` export serves
`src/codec.ts`, which re-exports exactly the codec names (the `numalgo4.ts`
functions, the two regexes, `MAX_LONG_FORM_LENGTH` and the `InputDocument` type)
and nothing from the driver. A DIDComm library that only needs encode and decode
imports the subpath and never loads `DidPeerDriver`, `@interop/bnid` or
`X25519KeyAgreementKey2020`. Node ESM does not tree-shake, so a single export
relying on `sideEffects: false` would not give that guarantee.

Dependency direction:

- `DidPeerDriver` depends on `numalgo4` and `inputDocument`.
- `numalgo4` and `inputDocument` depend on `constants`, `@scure/base`,
  `@noble/hashes`, `DIDResolutionError` from `@interop/data-integrity-core`, and
  shared helpers from `@interop/did-io`.
- `constants` and `types` depend on nothing in the package.

The two shared helpers imported from `@interop/did-io` are `contextsBySuite`
(the verification method type to context table) and `deepClone` (the guarded
clone). `VERIFICATION_RELATIONSHIPS` also comes from did-io. The codec is
therefore not dependency-free. It imports no key suite and does no I/O.

A later numalgo 2 module would sit beside `numalgo4.ts` as `numalgo2.ts`, and
`DidPeerDriver.get()` would dispatch on the numalgo digit. This release does not
implement it.

## Invariants

The rules the code upholds that a reader cannot infer from any one call site,
numbered so items and reviews can cite them. Each entry states the rule, why it
holds, and the code that upholds it. This list is what the design gate's
invariant inventory walks; an undocumented invariant is unprotected by the gate.

1. The hash is computed over the exact encoded-document string present in the
   DID, including its leading `z`. `decode` never re-serializes the document to
   verify it. The spec prescribes no canonicalization, so the hash covers
   whatever bytes the creator produced. Canonicalizing would make this library
   derive different DIDs from every other implementation (see
   `decisions/0001-no-input-document-canonicalization.md`). Upheld in
   `src/numalgo4.ts` `decode`. The test hashes the substring after the second
   `:` and compares.

2. Resolution never enforces the input document SHOULDs. `validateInputDocument`
   runs only on `generate()` paths. The method is self-certifying, so a document
   that violates a SHOULD still yields a sound DID, and rejecting a
   counterparty's DID over it buys nothing. Resolution does apply a structural
   guard, so that hostile hash-valid input yields `invalidDid` and a bare
   `TypeError` never escapes. Upheld by the contextualizer's guard, and by
   `resolveLongForm` and `resolveShortForm` not calling `validateInputDocument`.

3. Contextualization deep-copies before mutating. The caller's document,
   including nested method objects and arrays, is not mutated. Without the copy,
   resolving one decoded document as a long form and then as a short form would
   carry the first call's `controller` into the second. The test for an absent
   `controller` is an own-property test, so `controller: null` is left alone.
   Upheld in the contextualizer, using `deepClone` from did-io.

4. The library-generated input document never contains a root `id`, an absolute
   `id` on a resource, a `controller` on a method exported from a live key pair,
   or two resources with one id. A third-party method arrives as a ready-made
   `IVerificationMethodEntry` and keeps the `controller` it came with. The owner
   DID does not exist until after the hash is computed, so a live key pair
   always yields an owner-controlled method. Upheld by `addVerificationMethod`
   and by the `validateInputDocument` call on every `generate()` path. String
   references in relationships are not checked, so an absolute reference placed
   there by a caller-supplied `inputDocument` passes.

5. The only key suite imported at module load is `X25519KeyAgreementKey2020`,
   for `enableEncryptionKeyDerivation`. Every other suite arrives through
   `use()`. The codec subpath must not reach the driver or any key suite. Upheld
   by the import graph in `src/DidPeerDriver.ts`, and checked by a test over the
   compiled `dist/` import graph. That test also asserts that `dist/codec.js`
   reaches no driver module and no key suite.

6. A short form resolves only through the configured `LongFormStore`. The driver
   fills the store from `generate()` and from successful long form `get()` calls
   (when `rememberOnResolve` is on), and reads it for short forms. The driver
   keeps no memory of its own. A stored long form is used only when its own
   short form equals the one requested. Without that check, a store entry
   mapping one short form to a valid long form of another DID would resolve to
   the other DID's document. Upheld in `get()` steps 4 and 5 and in
   `generate()`.

7. The codec's resolved documents keep the input document's relative references
   unchanged. Everything the driver returns carries absolute DID URLs. That
   covers the document from `get({ did })` and `generate()`, the node from
   `get({ url })`, and the live key pairs with their map keys. One
   reference-resolution step produces them, against the DID the document was
   resolved under. The ecosystem's verifiers compare relationship entries to
   absolute method ids, so relative entries would fail every proof and
   capability signed by a did:peer key (see
   `decisions/0004-absolute-references-in-driver-output.md`). Upheld in the
   contextualizer (no rewriting) and in `DidPeerDriver` (rewriting in exactly
   one place).

8. Library-generated verification method fragments are the key's `fingerprint()`
   unless the caller overrides `fragment` (see
   `decisions/0003-fingerprint-fragment-convention.md`). The precondition is
   that the suite's `fingerprint()` equals its `publicKeyMultibase`. That holds
   for the Ed25519 and X25519 suites. A suite where it differs produces ids that
   do not repeat the key value. This is allowed but is not the documented shape.
   Upheld in `addVerificationMethod`.

9. `method` is the string `'peer'`, the second colon-separated segment of a
   did:peer DID. `CachedResolver.use()` keys on it and `parseDid` returns it.
   Upheld in `DidPeerDriver`.

10. The long form and short form regexes gate every string before decoding. The
    fixed `zQm` prefix and `{44}` length follow from base58 of a two-byte
    sha2-256 multihash header plus 32 digest bytes, which is 46 characters
    starting `Qm`. Any future hash would need new regexes. The `{6,}` bound on
    the encoded document is the reference's. The document `{}` encodes to
    exactly 6 characters, and no JSON object encodes shorter. Upheld in
    `src/numalgo4.ts`.

## Ownership heuristics

Where a given kind of change goes: which module owns which concern, and what
does not belong in this repo at all (points at the owning `@interop/*` package
or spec instead). This is the section that stops a shared concern from being
reimplemented locally.

Lives here:

- The numalgo 4 codec: encode, decode, hash, contextualize, the regexes and
  `MAX_LONG_FORM_LENGTH` (`src/numalgo4.ts`, `src/constants.ts`).
- The did-io driver: `generate()`, `get()`, `fromKeyPair()`,
  `publicKeyToDidDoc()`, `publicMethodFor()`, key suite registration through
  `use()`, the `LongFormStore` contract, and reference resolution
  (`src/DidPeerDriver.ts`, `src/types.ts`).
- Input document helpers: validation and assembly from key pairs
  (`src/inputDocument.ts`).

Lives elsewhere:

- Key suites (key generation, `export()`, `fingerprint()`, multibase headers)
  belong to `@interop/ed25519-verification-key` and
  `@interop/x25519-key-agreement-key`. A new key type means a new suite there.
- `findVerificationMethod`, `VERIFICATION_RELATIONSHIPS`, `contextsBySuite` and
  `deepClone` belong to `@interop/did-io`. Do not add a local copy. A fix to
  them is an in-house change upstream.
- `DIDResolutionError` and `VerificationMethodError` belong to
  `@interop/data-integrity-core`. The codec throws `DIDResolutionError` directly
  instead of a private error class, so `CachedResolver.resolveDID` produces the
  right envelope with no translation layer (see
  `decisions/0002-did-resolution-error-from-codec.md`). did-io 4.3.0 recognizes
  the error by `name` and `code`, so a duplicated data-integrity-core copy does
  not break the envelope.
- base58 comes from `@scure/base` and sha256 from `@noble/hashes`. Seed decoding
  comes from `@interop/bnid`. Do not vendor encoding primitives.
- A persistent `LongFormStore` belongs to the application. The driver defines
  the contract and ships no store class, because a `Map` satisfies it. The store
  implementer owns growth bounds and eviction.
- DID Resolution envelopes belong to `CachedResolver`. The driver has no
  `resolveDID()`.
- Numalgo 0 to 3 are out of scope. Numalgo 2 has a reserved slot in the layer
  map and deserves its own design.
- Remote JSON-LD context fetching is the consumer's documentLoader policy.

## Glossary

The repo's domain vocabulary: one canonical term per concept, used the same way
in code, tests, docs, commit messages, and conversation. This is the bounded
context's ubiquitous language in the domain-driven-design sense. A repo is one
bounded context; when a term carries a different meaning in a neighbouring repo,
the entry says so and points at that repo's glossary.

- **Input document** -- the id-less, relative-reference document a did:peer
  numalgo 4 DID is derived from. Lives in `src/inputDocument.ts` for building
  and validation. Avoid: genesis document, source document, DID doc template.
- **Encoded document** -- the multibase base58btc string of the
  multicodec-json-prefixed input document bytes. It is the part of a long form
  after the second `:`. Avoid: payload, blob.
- **Long form** -- `did:peer:4{hash}:{encoded document}`. Self-resolving. Avoid:
  full DID, expanded DID.
- **Short form** -- `did:peer:4{hash}`. Resolvable only through a stored long
  form. Avoid: hashed DID, compact DID.
- **Contextualize** -- the spec's term for adding `id`, `alsoKnownAs` and
  missing `controller`s to a decoded input document. It does not touch relative
  references. That is reference resolution. Lives in `src/numalgo4.ts`. Avoid:
  hydrate, expand, materialize.
- **Reference resolution** -- the driver step that rewrites a contextualized
  document's relative ids and relationship references to absolute DID URLs
  against the DID it was resolved under (DID Core's relative DID URL rule).
  Lives in `src/DidPeerDriver.ts`. The codec does not do it. Avoid: absolutize,
  expand, canonicalize.
- **Fragment** -- the part of a verification method or service id after `#`. For
  library-generated keys it is the key's multibase Multikey value
  (`fingerprint()`), as in did-method-key and did-web-resolver. Avoid: key ref,
  ident (the Python helper's word), key index.
- **Long form store** -- the `get`/`set` object the driver consults to resolve
  short forms (`LongFormStore` in `src/types.ts`). It is filled by `generate()`
  and, when `rememberOnResolve` is on, by long form resolution. Avoid: cache
  (that is `CachedResolver`'s word for its own LRU), registry.
- **Numalgo** -- the spec's name for the generation algorithm digit after
  `did:peer:`. This library implements numalgo 4 only. Avoid: version, method
  number.
- **Key suite** -- a registered key pair class (`use({ keyPairClass })`),
  identified by its four-character multibase header. Same meaning as in
  did-method-key and did-web-resolver. Avoid: key type (reserved for the
  `keyType` option that selects a suite), algorithm.

## Current State labels

Label structure that is aspirational as Desired Direction and areas
mid-migration as Transitional, in place, rather than describing the intended end
state as if it were current. A reader must be able to tell what holds today from
what is planned.

- Shipped: numalgo 4 only. The codec, the driver and the input document helpers
  described above are current.
- Shipped: numalgo 0 to 3 are rejected with `DIDResolutionError`
  `methodNotSupported`. The error message names the numalgo.
- Shipped: no persistent `LongFormStore` ships. A `Map` is the in-memory one.
  Without a store, every short form is `notFound`.
- Shipped: the driver does not implement `resolveDID()`. `CachedResolver` adapts
  `get()` into a resolution envelope and maps thrown `DIDResolutionError` codes.
- Transitional: `@interop/did-io` is consumed from a local checkout through a
  `file:` reference, pending the did-io 4.3.0 release (`contextsBySuite` and
  `deepClone`). Switch to `^4.3.0` when it lands. `@interop/data-integrity-core`
  already comes from the registry (8.10.0).
- Shipped: `MAX_LONG_FORM_LENGTH` is 4096 characters, matching the longest
  base58 string `@scure/base` decodes, so the length check runs before the
  decoder can refuse. The encoder's own limit of 2048 bytes of input bounds
  `encodeLongForm` and `generate()`, which fail with an `Error` naming the size.
- Desired Direction: numalgo 2 support, in its own module and design.
