# DMP-1: did:peer numalgo 4 codec and did-io driver (design)

- item: DMP-1
- status: approved
- approved: 2026-11-05
- wire-level decisions contained: listed in section 9 and individually signed
  off 2026-11-05
- decision records extracted:
  decisions/0001-no-input-document-canonicalization.md,
  decisions/0002-did-resolution-error-from-codec.md,
  decisions/0003-fingerprint-fragment-convention.md,
  decisions/0004-absolute-references-in-driver-output.md

## 1. Problem and scope

The `@interop` ecosystem has drivers for `did:key` (`@interop/did-method-key`)
and `did:web` (`@interop/did-web-resolver`), both pluggable into
`@interop/did-io`'s `CachedResolver`. It has no driver for `did:peer`. The
peer DID method spec defines numalgos 0 through 4. Numalgo 4 is the current
one: a statically resolvable method whose long form carries the whole DID
document inside the identifier, and whose short form is a hash of that encoded
document. It is the method DIDComm v2 agents exchange at first contact.

This library implements numalgo 4: the pure codec (encode, decode, hash,
contextualize), a did-io driver with `generate()`, `get()`, `fromKeyPair()`,
`publicKeyToDidDoc()` and `publicMethodFor()`, and input document helpers.

Out of scope for the first release:

- Numalgos 0, 1, 2 and 3. The module layout keeps room for numalgo 2 later
  (see section 4). `get()` rejects those DIDs explicitly instead of
  mis-parsing them.
- A DID Resolution `resolveDID()` implementation on the driver. `CachedResolver`
  already adapts `get()` into a resolution result envelope and maps thrown
  `DIDResolutionError`s to their codes.
- Persistence of long forms for later short-form resolution. The driver
  accepts a store object and defines its contract; it ships no persistent
  store of its own.

## 2. Reference material

- Spec: https://identity.foundation/peer-did-method-spec/, section "Method 4:
  Short Form and Long Form". Only that section applies to this library.
- Python reference, `decentralized-identity/did-peer-4`. Source of the test
  vectors in section 10 and of the input-document validation rules.
- TypeScript ports, `dbluhm/did-peer-4-ts` and `estoc-dev/did-peer`
  (`src/did-peer-4.ts`). The estoc port is the cleaner of the two and inlines
  the two multicodec prefixes as constants, dropping the `varint` dependency.
  This design does the same.
- Sibling drivers: `@interop/did-method-key` 7.5.1, `@interop/did-web-resolver`
  6.5.0, `@interop/did-io` 4.2.2.

## 3. Spec summary (numalgo 4)

Creating a DID starts from an input document. The input document looks like
the eventual DID document with four differences:

- no root `id`;
- every identifier defined in the document is relative (`#key-0`);
- every reference to a resource in the document is relative;
- a verification method omits `controller` when the controller is the
  document owner, and includes it otherwise.

Encoding:

1. JSON-stringify the input document without whitespace, encode as UTF-8,
   prefix with the multicodec `json` varint (`0x0200`, serialized as the two
   bytes `0x80 0x04`), multibase-encode as base58btc with the `z` prefix. This
   is the `encoded document`.
2. SHA2-256 the UTF-8 bytes of the encoded document string, prefix with the
   multihash header for sha2-256 (`0x12 0x20`), multibase-encode as base58btc.
   This is the `hash`.
3. Long form is `did:peer:4{hash}:{encoded document}`. Short form is
   `did:peer:4{hash}`.

The spec prescribes no canonicalization. The hash is over whatever bytes the
creator produced, so key order and formatting are preserved as given and
verified as given. Decoding never re-serializes.

Resolving a long form:

1. Split off the encoded document, recompute the hash, compare with the hash
   portion. Mismatch is a hard failure.
2. Decode the document (inverse of step 1 above).
3. Contextualize: set root `id` to the DID; ensure `alsoKnownAs` is a list and
   append the short form; for every verification method, whether listed under
   `verificationMethod` or embedded in a relationship, set `controller` to the
   DID if absent. Relative references stay relative. The spec notes that an
   implementation may make them absolute by prepending the DID but recommends
   against it for length, and this library follows that (section 6.2).

Resolving a short form requires having seen the long form. Contextualize the
decoded document with the short form as `id` and append the long form to
`alsoKnownAs`.

Matching regexes, from the Python reference (B58 is the bitcoin alphabet):

```
long:  ^did:peer:4zQm[B58]{44}:z[B58]{6,}$
short: ^did:peer:4zQm[B58]{44}$
```

The `zQm` prefix is fixed because every hash is a base58btc sha2-256 multihash.

## 4. Layer map

```
src/index.ts              Public entry point (the `.` export: codec + driver)
src/codec.ts              The `./codec` export: codec names only, no driver
src/DidPeerDriver.ts      DidPeerDriver: did-io DidMethodDriver for did:peer
src/numalgo4.ts           Pure codec: encode/decode/hash/contextualize, regexes
src/inputDocument.ts      Input document building (from key pairs) + validation
src/constants.ts          Context URLs, multicodec/multihash prefixes, defaults
src/types.ts              Shared types (KeyPairClass, FromMultibase, LongFormStore)
src/declarations.d.ts     Ambient shims, if any untyped dependency remains
```

Dependency direction: `DidPeerDriver` depends on `numalgo4` and
`inputDocument`; those two depend on `constants`, `@scure/base`,
`@noble/hashes`, the `DIDResolutionError` class from data-integrity-core
(section 8) and `VERIFICATION_RELATIONSHIPS` from did-io (the five
relationship names contextualization walks; house rules forbid redefining
them locally). The codec therefore is not dependency-free, but it imports no
key suite and does no I/O, so a DIDComm library that only needs encode/decode
can still use it without registering suites.

Key suites arrive through `use()`; the one suite imported at module load is
`X25519KeyAgreementKey2020`, for `enableEncryptionKeyDerivation`, exactly as
did-method-key does (invariant 5). `package.json` keeps `sideEffects: false`
so a bundler can drop the driver and that import when only the codec is used.

A later numalgo 2 module would sit beside `numalgo4.ts` as `numalgo2.ts`, and
`DidPeerDriver.get()` would dispatch on the numalgo digit. Nothing in this
design precludes that; nothing in this release implements it.

## 5. Dependencies

Runtime:

| package                               | why                                                           |
| ------------------------------------- | ------------------------------------------------------------- |
| `@interop/did-io`                     | `DidMethodDriver`, `DidGenerationResult` types; `findVerificationMethod`; `VERIFICATION_RELATIONSHIPS` |
| `@interop/data-integrity-core`        | `DIDResolutionError`, `VerificationMethodError`, `IDIDDocument`, `IPublicKey`, `AbstractKeyPair` types |
| `@interop/bnid`                       | `decodeSecretKeySeed` for `z1A...` string seeds (same as did-web-resolver) |
| `@interop/x25519-key-agreement-key`   | `X25519KeyAgreementKey2020.fromEd25519()` for opt-in key agreement derivation (same as did-method-key) |
| `@scure/base`                         | `base58` (bitcoin alphabet) for multibase `z` encoding        |
| `@noble/hashes`                       | `sha256` from `@noble/hashes/sha2.js`                         |

Dev only: `@interop/ed25519-verification-key` (the suite registered in tests
and README examples), plus the template's toolchain.

No `bs58`, no `varint`, no `multiformats`. The two multicodec prefixes are
two-byte constants. House rules forbid vendoring encoding primitives, and
`@scure/base` plus `@noble/hashes` are already the ecosystem's choices
(did-method-webvh, ed25519-verification-key).

Two dependency facts that shape the implementation:

- `CachedResolver.resolveDID()` recognizes the driver's errors with
  `instanceof DIDResolutionError` (did-io `src/CachedResolver.ts:198`), not by
  `name`/`code`. The "no translation layer" design in section 8 therefore
  requires that this package and did-io resolve to a single copy of
  `@interop/data-integrity-core`. Keep the `^8.x` range aligned with did-io's.
  Switching did-io to a `name`/`code` match is an in-house option recorded in
  section 16.
- The verification-method-type to context table that `get({ url })` step 6
  needs (`Ed25519VerificationKey2018`, `Ed25519VerificationKey2020`,
  `Multikey`, `X25519KeyAgreementKey2019`, `X25519KeyAgreementKey2020`,
  `JsonWebKey2020`) exists as a private constant in did-method-key
  (`src/helpers.ts:46`) and as an unexported module value in did-web-resolver
  (`src/constants.ts:37`). Neither package exports it. House rules forbid a
  third copy, so the table must be exported upstream first (section 16 names
  the candidate home). Until then this item blocks step 6.

## 6. Public API

### 6.1 Exports (`src/index.ts`)

```ts
export { driver, DidPeerDriver } from './DidPeerDriver.js'
export {
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
  SHORT_FORM_PATTERN,
} from './numalgo4.js'
export { validateInputDocument } from './inputDocument.js'
export type {
  DidPeerDriverOptions,
  FromMultibase,
  InputDocument,
  KeyPairClass,
  LongFormStore,
} from './types.js'
```

`driver(options?)` is a one-line factory returning `new DidPeerDriver(options)`,
matching did-web-resolver (did-method-key's `driver()` takes no options).

The root barrel exports codec and driver together under the `.` export, as the
siblings do. In addition (decided 2026-11-05) the package has a `./codec`
subpath export, `@interop/did-method-peer/codec`, served by `src/codec.ts`,
which re-exports exactly the codec names above (the `numalgo4.ts` functions,
`LONG_FORM_PATTERN`, `SHORT_FORM_PATTERN`, `MAX_LONG_FORM_LENGTH` and the
`InputDocument` type) and nothing from the driver. A DIDComm library importing
from the subpath never loads `DidPeerDriver`, `@interop/bnid` or
`X25519KeyAgreementKey2020`, whatever its bundler does; it still loads
data-integrity-core (for `DIDResolutionError`) and did-io (for
`VERIFICATION_RELATIONSHIPS`), per section 4. The export map carries the same
four conditions for `./codec` as for `.` (`types`, `react-native`, `import`,
`default`), and the `dist/` import-graph test in invariant 5 also asserts that
`dist/codec.js` reaches no driver module.

### 6.2 Pure codec (`src/numalgo4.ts`)

All functions are synchronous. `@noble/hashes` sha256 is synchronous, and
nothing here touches the network or a key suite. The driver's `get()` is still
`async` because the did-io contract says so.

```ts
export type InputDocument = Record<string, unknown>

export function encodeLongForm({ inputDocument }: { inputDocument: InputDocument }): string
export function encodeShortForm({ inputDocument }: { inputDocument: InputDocument }): string
export function decode({ did }: { did: string }): InputDocument
export function longToShort({ did }: { did: string }): string
export function isDidPeer4(did: string): boolean    // startsWith 'did:peer:4'
export function isLongForm(did: string): boolean
export function isShortForm(did: string): boolean
export function resolveLongForm({ did }: { did: string }): IDIDDocument
export function resolveShortForm({ longFormDid }: { longFormDid: string }): IDIDDocument
```

Behavior:

- `encodeLongForm` and `encodeShortForm` do not validate. Validation is the
  driver's job at `generate()` time (section 6.4). This matches the Python
  `encode(validate=False)` path and keeps the `{"hello":"world"}` vector
  reproducible.
- `decode` rejects a non-`did:peer:4` string, a short form (document not
  recoverable), a string failing the long-form regex, a hash mismatch, and a
  decoded payload that is not a plain object (`null`, an array, a string, a
  number; `typeof x === 'object'` alone is not the test, since `null` and
  arrays pass it and a spread of `null` would resolve to `{ id, alsoKnownAs }`
  with no error). The hash is computed over the encoded-document string
  including its leading `z`, matching the Python reference. `decode` returns
  the parsed document; the caller never sees the string again, so a fresh
  parse per call is what makes the copy rule below cheap.
- `decode` also rejects a long form longer than `MAX_LONG_FORM_LENGTH` before
  hashing or base58-decoding it. The hash is attacker-computed, so the hash
  check protects against corruption only, not against a hostile sender; the
  regex has no upper bound, and base58 decoding plus `JSON.parse` of a
  multi-megabyte DID string would block the event loop. The constant is 4096
  characters (decided 2026-11-05; revised the same day from 16384 to match the
  longest base58 string `@scure/base` decodes), roughly four times the largest
  published vector and about 2.8 KB of JSON after base58 expansion; it lives in
  `constants.ts`, is exported so callers can see it, and is not configurable
  until a consumer needs more.
- `longToShort` is regex-guarded string surgery only; it does not verify the
  hash. Callers that need the hash verified call `decode` first.
- `resolveLongForm` is `decode` followed by contextualization with the long
  form as `id`, appending the short form to `alsoKnownAs`.
- `resolveShortForm` takes the long form, decodes it (so the regex and hash
  checks run), contextualizes with the short form as `id`, appends the long
  form to `alsoKnownAs`. The Python `resolve_short_from_doc(document, did)`
  variant is covered by
  `resolveShortForm({ longFormDid: encodeLongForm({ inputDocument }) })` plus
  the caller's own equality check, so it is not a separate export. Note that
  this re-derivation path is the one place where serialization differences
  matter (section 9 item 7): a document that a Python agent created with
  non-ASCII text re-encodes to a different long form here.
- Contextualization is total over hash-valid input. The input document comes
  from the counterparty and the hash proves integrity, not shape, so the
  contextualizer must never let a bare `TypeError` escape (section 8 promises
  `DIDResolutionError` from the codec, and `CachedResolver.resolveDID` maps
  anything else to `internalError`). Rules, matching the Python reference
  where it has one and throwing `invalidDid` where Python would crash:
  - `alsoKnownAs` absent: created as `[shortForm]`. An array: the form is
    appended (so it is the last entry, not the first). Anything else:
    `invalidDid`.
  - A root `id` already present is overwritten; the original is discarded.
  - `verificationMethod` and each of the five relationships: an array is
    walked; absent is skipped; anything else is `invalidDid`. Within an
    array, a plain object gets `controller` set when it has no own
    `controller` property (`Object.hasOwn`, not a truthiness check, so
    `controller: null` is left alone as in Python); a string is a reference
    and is left alone; anything else is `invalidDid`.
  - `publicKey` and `service` are not walked.
  - Every other property is copied through untouched. `alsoKnownAs` entries
    other than the appended one, and any `controller` naming a different DID,
    are unverified claims by the counterparty; the library passes them
    through and does not flag them.
- The codec's contextualization leaves relative references relative, exactly
  as the spec and both reference implementations do, so codec output compares
  with the Python reference's output content for content (section 10). The
  driver's `get()` output does not stay relative: it applies reference
  resolution (section 6.4, after step 5) so that the ecosystem's verifiers,
  which compare relationship entries to absolute method ids, accept did:peer
  controller documents. The split is deliberate: the codec is the spec, the
  driver is the ecosystem's view of it. See section 9 item 5.
- Contextualization returns a deep copy, then mutates the copy. A shallow
  spread would still set `controller` on the caller's nested method objects
  and push onto the caller's `alsoKnownAs` array; resolving the same decoded
  document as long form and then as short form would then carry the first
  call's `controller` into the second. The reference implementations mutate in
  place. The clone primitive is did-io's `deepClone`, which calls
  `structuredClone` (available in every supported browser, Node and current
  React Native). `JSON.parse` output can carry an own `__proto__` property;
  `structuredClone` preserves it as an own key, while assignment-style copies
  would set the prototype, so no `Object.assign` or `target[key] = value`
  loops over parsed input.
- Runtime primitives, for the browser and React Native targets: `TextEncoder`
  and `TextDecoder` for the UTF-8 steps, `base58` from `@scure/base`, `sha256`
  from `@noble/hashes/sha2.js`. No `Buffer`, no `atob`/`btoa`. `tsconfig` has
  the DOM lib, so type-checking will not catch a Node-only API; the browser
  suite is the guard.
- Errors thrown by the codec are `DIDResolutionError` with `code: 'invalidDid'`
  (see section 8).

Why `encodeLongForm`/`encodeShortForm` rather than the reference's
`encode`/`encode_short`: the glossary (section 11) makes "long form" and
"short form" the two canonical terms, and a bare `encode` says nothing about
which one comes back.

### 6.3 Input document helpers (`src/inputDocument.ts`)

```ts
export function validateInputDocument({ inputDocument }: { inputDocument: InputDocument }): void
```

Deliberately superficial, matching the Python `validate_input_document`
docstring. Checks:

- the document is a non-null, non-array object and not empty;
- no root `id`;
- `alsoKnownAs`, if present, is an array;
- `verificationMethod`, the five relationships and `service` are arrays if
  present;
- every embedded resource (object entry in any of those arrays) has a string
  `id` starting with `#`, and a `type`;
- (this library only, beyond the Python rules) resource ids are unique
  across `verificationMethod`, embedded relationship entries and `service`.
  Without it, the same key passed as `verificationKeyPair` and again in
  `verificationMethods`, or two entries with one `fragment`, yields two
  methods with one id, the `keyPairs` map silently keeps only the later live
  pair, and `get({ url })` returns whichever comes first.

String entries in relationships are references and are not checked. They may
legitimately point at another DID's key (the estoc port's rationale). Content
validation of key material is left to the suites and to the caller after
resolution. These rules accept `{"hello":"world"}` (vector 0), as the Python
`validate_input_document` does (section 10, vector 0).

Validation is applied on every `generate()` path, including path 3 where the
library built the document itself (so `fragment` overrides such as `''` or
`'#x'` are caught). It is not applied on resolution. The method is
self-certifying, so a document that violates a SHOULD still produces a sound
DID, and rejecting a counterparty's DID over it buys nothing. Resolution has
its own structural guard inside contextualization (section 6.2), which is a
different thing: it exists so hostile input cannot crash the resolver, not to
enforce the SHOULDs.

A second, internal helper assembles an input document from key pairs. It is
the did:peer analogue of did-web-resolver's `addVerificationMethod` and is what
`generate()` without an `inputDocument` calls:

```ts
function addVerificationMethod({
  inputDocument, keyPair, fragment, purposes,
}): { inputDocument; fragment }
```

It exports the public key node with `includeContext: true`, moves the node's
`@context` into the document's `@context` (de-duplicated), sets the node's
`id` to the relative `#${fragment}`, handles `controller` per the rule below,
stores the node under `verificationMethod`, and appends the relative id string
to each purpose. Embedding a clone of the node in each relationship (the
`embed` option of did-web-resolver's helper) is not offered; nothing in this
library would pass it, and a caller wanting embedded methods builds the input
document directly.

The `controller` rule. The spec says a method omits `controller` when the
controller is the document owner and includes it otherwise. The owner DID does
not exist until after the hash is computed, so "owner-controlled" cannot be
read off the key pair: a pair that was bound by an earlier `generate()` carries
that earlier peer DID as its `controller`, and `Ed25519VerificationKey`
derives `id` from `controller` at construction, so an exported node always
carries some controller and an absolute id. The helper therefore strips both
from every node it exports from a live key pair: a live pair always yields an
owner-controlled method. A third-party-controlled method is expressed the way
DID Core expresses one, as a ready-made `IVerificationMethodEntry` from
data-integrity-core passed in `verificationMethods` (decided 2026-11-05,
section 6.4 path 3): either a string reference, an absolute DID URL to a key
defined in another DID document, or a full `IVerificationMethod` object whose
`controller` names the other DID. The helper places such an entry verbatim. A
string is appended to each purpose and nothing is added to
`verificationMethod`; an object is stored under `verificationMethod` and
referenced from each purpose, its `controller`
kept as given and its `id` required to be relative by validation. No live pair
is bound for it, so `methodFor()` for such a method throws like any unbound
method.

Key agreement derivation happens from the live Ed25519 key pair, not from the
stripped node: `X25519KeyAgreementKey2020.fromEd25519()` takes `controller`
and `publicKeyMultibase`, and without a `controller` the derived pair has no
`id`, so its exported node could not be referenced. The helper derives first,
then runs the derived pair through the same export-and-strip path with its own
`fingerprint()` as fragment.

The default `fragment` is the key pair's `fingerprint()`, the multibase
Multikey value (`z6Mk...` for Ed25519, `z6LS...` for X25519), so a generated
method is `#z6Mk...`. This is the convention did-method-key, did-web-resolver
and did-method-webvh use, and it keeps `keyPairs` lookups and
`methodFor()` consistent across drivers. A caller may pass `fragment` to
override it per key.

### 6.4 `DidPeerDriver` (`src/DidPeerDriver.ts`)

```ts
export class DidPeerDriver implements DidMethodDriver {
  method = 'peer'
  constructor({ longFormStore, rememberOnResolve = true }: DidPeerDriverOptions = {})
  use({ keyPairClass, multibaseMultikeyHeader, fromMultibase, enableEncryptionKeyDerivation }): void
  generate(options?): Promise<DidGenerationResult>
  fromKeyPair({ verificationKeyPair, keyAgreementKeyPair }): Promise<DidGenerationResult>
  publicKeyToDidDoc({ publicKeyDescription }): Promise<{ didDocument: IDIDDocument }>
  get({ did, url }): Promise<IDIDDocument | IPublicKey>
  publicMethodFor({ didDocument, purpose }): IPublicKey
}
```

`method = 'peer'` is what `CachedResolver.use(driver)` keys on; `parseDid`
returns `peer` for `did:peer:4zQm...`.

#### `use()`

The same two forms as did-method-key. Preferred: `use({ keyPairClass })`
where the class has static `multibaseHeader`, `from` and optionally
`generate`. Lower-level: `use({ multibaseMultikeyHeader, fromMultibase })`.
Registry keyed by the 4-character multibase header (`z6Mk`, `z6LS`, `zDna`).
`from` is stored bound to its class (`keyPairClass.from.bind(keyPairClass)`),
as did-web-resolver does; did-method-key stores it unbound, which only works
for suites whose `from` never touches `this`. `X25519KeyAgreementKey2020` has
no static `multibaseHeader`, so an X25519 suite can only be registered through
the lower-level form; `enableEncryptionKeyDerivation` does not need it
registered.
`enableEncryptionKeyDerivation` (default `false`) opts an Ed25519 suite into
producing a derived X25519 `keyAgreement` key, through
`X25519KeyAgreementKey2020.fromEd25519()`, exactly as did-method-key does.
It is opt-in for the same reason there: using one key's material for both
signing and encryption is a posture choice the caller makes.

#### `generate()`

Three mutually exclusive entry paths, chosen by which option is present:

```ts
generate({
  inputDocument?: InputDocument,
  keyPairs?: Map<string, AbstractKeyPair>,   // only with inputDocument; keyed by relative fragment
  seed?: string | Uint8Array,
  keyType?: KeyPairClass | string,
  verificationKeyPair?: AbstractKeyPair | IKeyPair,
  keyAgreementKeyPair?: AbstractKeyPair | IKeyPair,
  verificationMethods?: Array<
    | { keyPair: AbstractKeyPair | IKeyPair; fragment?: string; purposes?: string[] }
    | { method: IVerificationMethodEntry; purposes: string[] }  // third-party, explicit purposes
    | IVerificationMethodEntry   // third-party: string reference or full method object
  >,
  service?: object[],
} = {}): Promise<DidGenerationResult>
```

1. `inputDocument` given. Validate it, encode, resolve the long form. If
   `keyPairs` is given, it is keyed by bare fragment (the glossary's sense:
   the part after `#`, so `z6Mk...` or `key-0`; `#key-0` is not a fragment),
   the same form the `fragment` option takes everywhere else. For each entry
   the driver checks that the document has a method with id `#${fragment}`, in
   `verificationMethod` or embedded in a relationship, and that its public key
   equals the pair's: a method with `publicKeyMultibase` is compared directly,
   and any other serialization (`publicKeyBase58`, `publicKeyJwk`) is rebuilt
   through the pair's registered suite and compared by fingerprint, so the
   suite decides which serializations it reads. A missing method or a mismatch
   is a `TypeError`, since binding
   a live signer to foreign public material would hand `methodFor()` a key
   that cannot verify. It then sets the pair's `controller` to the long form
   and `id` to `${longForm}#${fragment}`, and re-keys the returned map by
   that full id. Methods without a live pair are allowed; `methodFor()` for
   such a method throws (below). Combining `inputDocument` with `seed`,
   `keyType`, `verificationKeyPair`, `keyAgreementKeyPair`,
   `verificationMethods` or `service` is a `TypeError`, and so is `keyPairs`
   without `inputDocument`.
2. `seed` given (`string` in bnid `z1A...` form, or a `Uint8Array` of exactly
   32 bytes). Decode as did-web-resolver does, generate one key pair with the
   selected or sole registered suite, then proceed as path 3 with that pair
   as `verificationKeyPair`. `seed` together with `verificationKeyPair` is a
   `TypeError` (two sources for one slot).
3. Nothing, or explicit pairs. If neither `verificationKeyPair` nor
   `verificationMethods` is given, generate one random key pair with the
   selected or sole registered suite. `keyType` with an explicit
   `verificationKeyPair` is a `TypeError` (it would be silently ignored
   otherwise). Build the input document:
   - `@context` starts as `['https://www.w3.org/ns/did/v1']`; suite contexts
     are appended by `addVerificationMethod`.
   - The verification key, when there is one, is added first and gets the
     default purposes `authentication`, `assertionMethod`,
     `capabilityDelegation`, `capabilityInvocation`, the same four as both
     siblings. With `verificationMethods` and no `verificationKeyPair`, no
     default-purpose key is added and nothing is derived: the caller owns the
     whole key set.
   - `keyAgreementKeyPair`, if given, is added with purpose `keyAgreement`. If
     not given, the verification key is an Ed25519 pair, and its suite was
     registered with `enableEncryptionKeyDerivation`, a derived X25519 key is
     added instead. The derived pair is an `X25519KeyAgreementKey2020` whose
     exported node carries that type and the
     `https://w3id.org/security/suites/x25519-2020/v1` context, which is
     appended to `@context` (section 7). A caller-supplied
     `keyAgreementKeyPair` of any type is accepted and its own exported
     context is appended the same way; did-method-key's hard-coded
     X25519-only context table is not copied.
   - `verificationMethods` entries are added next, in order. A `{ keyPair }`
     entry is exported and stripped with its `fragment` and `purposes`, as in
     did-web-resolver. A bare `IVerificationMethodEntry` (a string DID URL, or
     an `IVerificationMethod` object with its own `id`, `type`, `controller`
     and key material) is a third-party method placed verbatim (section 6.3)
     and gets the same default four purposes as the verification key; a caller
     needing other purposes for a third-party method wraps it as
     `{ method, purposes }`. An entry whose `purposes` include
     `keyAgreement` alongside a derived or supplied key agreement key yields
     two `keyAgreement` methods; `methodFor()` returns the first.
   - `service`, if given, is copied as-is.
   Then validate the assembled document (section 6.3 rules, including id
   uniqueness), encode, resolve the long form, and bind the live pairs as in
   path 1.

All three paths finish the same way: bind the live pairs, then, when a
`longFormStore` is configured, `await longFormStore.set(shortForm, longForm)`,
then return. A rejected `set` rejects `generate()`; the caller then holds no
DID and may retry, which on the random path mints fresh keys and on the seed
or input-document paths re-derives the same DID (so a retry re-`set`s the same
pair, idempotently). The store record means only "this long form is known",
never "generate completed". Because `set` is awaited, `generate()` followed by
`get({ did: shortForm })` on the same store hits, provided the store is
read-your-writes.

Return value is the did-io `DidGenerationResult`:

```ts
{ didDocument, keyPairs, methodFor }
```

`didDocument.id` is the long form. For a generated document
`didDocument.alsoKnownAs[0]` is the short form; for a counterparty's document
the appended form is the last entry and the others are unverified, so general
code derives the short form with `longToShort` instead of indexing. `keyPairs`
is keyed by full key id (`${longForm}#${fragment}`), the same value set on
each live pair's `id` and the same value the returned `didDocument` carries
after reference resolution (section 6.4). `methodFor({ purpose })` therefore
looks up the id that `publicMethodFor` returns directly. It returns the live
pair, and throws
both when no method serves the purpose (`publicMethodFor`'s own error) and
when the method exists but has no live pair in the map (possible after path 1
with a partial `keyPairs`). Neither sibling throws on the second case: both
return `keyPairs.get(id)!`. The throwing form is the one did-io documents and
the one this driver uses.

Suite selection errors reuse did-web-resolver's messages verbatim, since that
driver also has a `verificationKeyPair` option: `No key suite registered; call
"use({keyPairClass})" or pass a "verificationKeyPair".`, `Multiple key suites
registered; specify which via "keyType" or pass a "verificationKeyPair".`, and
`Registered suite "<h>" cannot generate keys; register it via
"use({keyPairClass})".` (did-method-key's first two differ by that clause.)

#### `fromKeyPair()`

Requires at least one of `verificationKeyPair`, `keyAgreementKeyPair`
(`TypeError` otherwise) and delegates to `generate()` path 3. Either argument
may be a plain `IKeyPair` description rather than a live `AbstractKeyPair`
(the did-io contract allows it); a plain description has no `fingerprint()`
or `export()`, so it is first rebuilt through the registered `fromMultibase`
for its `publicKeyMultibase` header, and a description with no
`publicKeyMultibase` is a `TypeError`. With only `keyAgreementKeyPair`, no
signing key is generated: the document carries the one key under
`keyAgreement`, as did-method-key does.

#### `publicKeyToDidDoc()`

Rebuilds a key pair from a public description via the registered
`fromMultibase` (header from `publicKeyMultibase`), classifies it as
did-method-key's `getKeyPair` does (an `X25519KeyAgreementKey2019`/`2020` or
`z6LS` description becomes the `keyAgreementKeyPair`, anything else the
`verificationKeyPair`), then returns only `{ didDocument }` from `generate()`
path 3. Same shape as both siblings. It does not write the `longFormStore`:
it is a pure conversion of public material and nobody holds keys for the
resulting DID.

#### `get()`

```ts
async get({ did, url }: { did?: string; url?: string } = {})
```

1. `did = did ?? url`; neither is a `TypeError`. `CachedResolver.get` always
   forwards the string as `did`, whatever the caller passed, so the `url`
   option is only reached by direct driver calls.
2. Split off the DID URL parts. The authority ends at the first `#`, `?` or
   `/`. A `?query` or `/path` is stripped and ignored (decided 2026-11-05):
   the authority is resolved and the fragment, if any, is still honored, as
   did-web-resolver does with its `/[#?]/` split. The driver does not
   dereference query parameters; a DIDComm `?service=` URL therefore yields
   the document or the fragment's node, the same as the bare DID would.
   `CachedResolver` memoizes on the raw string, so URLs differing only in
   query are separate cache entries. More than one `#` is `DIDResolutionError`
   `invalidDidUrl`. An empty fragment (`did#`) is
   treated as no fragment.
3. Reject anything not starting with `did:peer:` with `DIDResolutionError`
   `methodNotSupported`. The numalgo digit is the single character after
   `did:peer:`; when it is a digit other than `4`, throw `methodNotSupported`
   with a message naming the numalgo (wire-level, section 9 item 4). When it
   is missing or not a digit, the string is malformed: `invalidDid`.
4. Authority matching the long-form regex: `resolveLongForm`. On success, if a
   `longFormStore` is configured and `rememberOnResolve` is on (the default),
   `await set(shortForm, longForm)` so the counterpart's short form resolves
   later. Write policy and failure handling are in section 6.5. Authority matching the short-form regex: step 5.
   Matching neither: `invalidDid`.
5. Short form: `const stored = await longFormStore.get(shortForm)`. A result
   that is not a non-empty string is a miss, and so is having no store; a miss
   throws `DIDResolutionError` `notFound` with a message saying the long form
   has not been seen. A store that throws or rejects is a store failure, not
   a miss: it surfaces as `DIDResolutionError` `internalError` with the store
   error as `cause`, so the caller does not conclude the long form was never
   seen. A hit that is not a long form at all is also a store failure
   (`internalError`), since the requested DID is well formed and the defect is
   the store's. On a hit, `longToShort(stored)` must equal the requested short
   form; a mismatch is `invalidDid`. Without this check a store entry mapping
   `shortA` to a valid long form of another DID would resolve to that other
   DID's document under `id` of the other DID, and `CachedResolver` would
   cache it under `shortA`; decoding the stored long form only proves it
   matches its own hash. Python's `resolve_short_from_doc` has the same
   equality check, and the driver is the one place here that holds both
   strings. Then `resolveShortForm`. The read path never writes the store.
6. No fragment: return the document. With a fragment: find the node whose
   `id` is `#${fragment}` or `${authority}#${fragment}` (the requested
   authority, so a counterparty document carrying absolute ids under the other
   form is not matched; such documents are off-spec and the library does not
   normalize them), searching `verificationMethod` first, then embedded
   relationship entries, then `service`. A fragment present in more than one
   place resolves to the first found; DID Core requires unique ids and
   resolution does not validate, so the shadowing is stated here rather than
   detected. The legacy `publicKey` array (vector 6) is not searched, so its
   keys are not dereferenceable by URL, matching did-io's `findVerificationMethod`.
   Return a deep clone with `id` made absolute (`${authority}#${fragment}`)
   and an `@context`: the context for the node's `type` from the shared
   type-to-context table (section 5; a blocking upstream export), falling
   back to a clone of the document's `@context` as did-web-resolver's
   `getNode` does (did-method-key's `getKey` has no fallback and searches
   only two arrays; the did-web shape is the more general one). A type not in the table and a document with no `@context`
   leaves the node without one, and the node is returned as-is; it is then
   unusable for JSON-LD processing but still a valid plain lookup result.
   The document's `@context` is counterparty-supplied and flows into
   jsonld framing in verifiers; remote context fetching is the consumer's
   documentLoader policy (security-document-loader defaults it off). Not
   found is `VerificationMethodError` with `code: 'notFound'`, as in both
   siblings.

Reference resolution (between step 5 and step 6, decided 2026-11-05, section 9
item 5). The driver takes the codec's contextualized document and resolves
every relative reference against the DID it was resolved under, per DID Core's
rule for relative DID URLs: the `id` of every object entry in
`verificationMethod`, the five relationships and `service`, and every string
entry in the five relationships, becomes `${authority}#${fragment}` when it
starts with `#`. Entries that are already absolute (a reference to another
DID's key, or an off-spec counterparty document) are left as they are. Nothing
else is touched: `controller` values are already absolute, `alsoKnownAs` holds
DIDs, and service endpoint contents are opaque. The result is the DID
document the driver returns, with the same shape did:key and did:web
documents have, and step 6 searches it (so the node lookup matches on the
absolute id). The codec's `resolveLongForm`/`resolveShortForm` stay relative
and spec-pure; the driver test in section 10 compares against the codec
output after applying the same resolution.

Two forms, one key. A node fetched by long-form URL carries the long form in
`id` and `controller`; the same node fetched by short-form URL carries the
short form in both. No verifier in the ecosystem treats `alsoKnownAs` as an
equivalence, so a proof whose `verificationMethod` names one form and whose
capability `controller` names the other fails authorization. Wallets put the
long form in `proof.verificationMethod` and in zcap `controller` fields: it is
self-resolving and survives a lost store. The README says so.

#### `publicMethodFor()`

Same as both siblings: `findVerificationMethod({ doc, purpose })` from did-io,
`TypeError` for a missing argument, `Error('No verification method found for
purpose "<p>"')` for a miss. Returns the public node without `@context`.

Checked against did-io 4.2.2: with `purpose`,
`findVerificationMethod` takes the relationship's first entry and, for a
string, looks it up by exact `method.id === methodId` (`src/did-io.ts:126-152`).
After reference resolution both sides are the same absolute string in a
driver-returned document, so purpose lookups, `methodId` lookups with the ids
that `keyPairs`, `methodFor().id` and `get({ url })` hand out, and
`approvesMethodFor` all work, exactly as for did:key and did:web documents.
On a codec-returned (relative) document only purpose lookups work, which is
why `publicMethodFor` is documented for driver output. did-io also takes only
the first entry of a relationship, so a document whose first `authentication`
entry is a reference to another DID's key makes `publicMethodFor` throw "No
verification method found" even when a later local entry would serve; that is
a did-io behavior shared by every driver and not changed here.

### 6.5 `LongFormStore`

The problem it solves. A long form carries its own DID document, so resolving
it needs nothing but the string. A short form is only the hash. The spec says
so directly: "It is not possible to resolve a short form did:peer:4 without
first seeing and storing its long form counterpart." In practice a DIDComm
peer sends its long form once, at first contact, and its short form in every
message after that. Whoever resolves those later messages has to remember
which long form the short form belongs to.

`LongFormStore` is that memory. It is a lookup from short form to long form
that the caller hands the driver at construction:

```ts
export interface LongFormStore {
  get(shortForm: string): string | undefined | Promise<string | undefined>
  set(shortForm: string, longForm: string): unknown
}
```

How the driver uses it:

- `get({ did })` with a long form, on success, calls
  `await set(shortForm, longForm)`. Seeing a counterparty's long form once is
  enough for its short form to resolve from then on.
- `generate()` calls `await set(shortForm, longForm)` for the DID it just
  created, so the creator can resolve its own short form.
  `publicKeyToDidDoc()` does not write.
- `get({ did })` with a short form calls `await get(shortForm)` and applies
  the checks in section 6.4 step 5. The read path never writes.

Both methods are awaited whether they return a value or a promise, so a
promise-returning persistent store is honored and a `Map` works unchanged.

What the driver stores is the long form string only. The input document is
recoverable from it by `decode`. The stored value is verified twice on the way
out: `decode` checks the long form against its own hash (a corrupted entry
fails as `invalidDid`), and step 5 checks that the long form's short form is
the one that was asked for (a mis-keyed or poisoned entry fails as
`invalidDid` instead of resolving to another DID's document).

Write policy. The driver always writes an unconditional overwrite: the pair
it writes is derived from one string, so two different long forms can never
claim one short form, and overwriting a corrupt entry is the only repair path
(the interface has no `delete`). Writes are idempotent, so two drivers sharing
a store, or a retry, are safe. A write-on-sight store grows by one entry per
distinct long form resolved, and any counterparty can mint unlimited distinct
long forms, so a persistent store is unbounded by construction; the store
implementer owns bounds and eviction and the README says so.

The `rememberOnResolve` option (decided 2026-11-05). Writes on resolution are
controlled by the boolean constructor option `rememberOnResolve`, default
`true`. DIDComm clients keep the default, since the counterparty sends its long
form once and short forms after. A verifier that only fetches key nodes for
signature checks sets it to `false`: it gains nothing from the entries, and
with it on, every key fetch would be a durable write and a store failure would
fail the verification. With it off, a configured store is read-only from the
driver's side except for `generate()`, which always writes, so an application
can seed the store itself. No `remember()` method is exposed; an application
wanting contact-acceptance gating resolves with `rememberOnResolve: false` and
writes `set(longToShort({ did }), did)` into its own store when it accepts.

Write failure. A rejected `set` in `generate()` rejects `generate()` (section
6.4). A rejected `set` in `get({ did: longForm })` rethrows as
`DIDResolutionError` `internalError` with the store error as `cause`, failing
the resolution even though the document itself was computed (decided
2026-11-05). The alternative, swallowing it, would leave every later short form
from that peer `notFound` with no trace; a loud failure is the only one a
caller can act on, and a caller who wants best-effort persistence wraps their
own store's `set`. A store `get` failure is `internalError` with `cause` (step
5). It is not reported as `notFound`.

Ordering guarantee. Because `set` is awaited before `get()` or `generate()`
returns, a caller that awaits the long-form resolution before processing the
next message is guaranteed the short form hits afterwards, if the store is
read-your-writes. A caller that processes a short-form message concurrently
with the first-contact long form has a race the driver cannot close.

`get({ url })` for a key node also passes through step 4 and therefore writes
when `rememberOnResolve` is on; every documentLoader fetch of a did:peer key
is then a store write. The write is idempotent and `CachedResolver` memoizes
the result for its TTL, so the cost is one write per key per TTL window.

Positional parameters are deliberate here, against the house options-object
rule, so that a plain `Map<string, string>` satisfies the interface
structurally and in-memory use needs no class from this package:

```ts
const didPeerDriver = driver({ longFormStore: new Map() })
```

A persistent store (IndexedDB, a wallet's encrypted storage) implements the
same two methods, returning promises. There is no default store. Without one,
every short form is `notFound`, which is the honest statement of the method:
the driver has nowhere to have seen the long form.

This is distinct from `CachedResolver`'s LRU cache. That cache memoizes
successful `get()` results for 5 seconds by exact DID string and knows nothing
about the relationship between a short and a long form. Rejections are not
cached (lru-memoize deletes a rejected promise from the cache; did-io's
`resolveDID` header comment says the same), so a short-form `notFound`
followed by a long-form sighting followed by the short form again, all within
the TTL, resolves. Two consequences remain: a cached long-form success skips
the driver, so a failed `set` is not retried until the TTL lapses; and a
short-form success stays served from the cache for the TTL after the store
entry changes, which is harmless because the mapping is immutable. If the
driver ever gains its own `resolveDID()` (section 1 excludes it), note that
`CachedResolver.resolveDID` does cache error envelopes, which would make a
short-form `notFound` stick for the TTL. The store is a durable mapping, lives
as long as the relationship does, and is consulted only for short forms.

### 6.6 did-io integration

```ts
import { CachedResolver } from '@interop/did-io'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import * as didPeer from '@interop/did-method-peer'

const didPeerDriver = didPeer.driver({ longFormStore: new Map() })
didPeerDriver.use({ keyPairClass: Ed25519VerificationKey, enableEncryptionKeyDerivation: true })

const resolver = new CachedResolver()
resolver.use(didPeerDriver)

const { didDocument, keyPairs, methodFor } = await didPeerDriver.generate()
await resolver.get({ did: didDocument.id })                 // long form, offline
const signingKey = methodFor({ purpose: 'authentication' })
await resolver.get({ url: signingKey.id })                  // key node, `${longForm}#z6Mk...`
await resolver.get({ did: didDocument.alsoKnownAs[0] })     // short form, via store
```

`CachedResolver.generate({ method: 'peer', ...args })` also works because the
driver exposes `generate`. `CachedResolver.resolveDID()` adapts `get()` and
maps the `DIDResolutionError` codes above into the resolution envelope.

## 7. Generated document shape

With the README setup above (Ed25519 suite, derivation on), `generate()` with
no arguments yields this input document before encoding:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1",
    "https://w3id.org/security/suites/x25519-2020/v1"
  ],
  "verificationMethod": [
    { "id": "#z6MkABC...", "type": "Multikey", "publicKeyMultibase": "z6MkABC..." },
    { "id": "#z6LSXYZ...", "type": "X25519KeyAgreementKey2020", "publicKeyMultibase": "z6LSXYZ..." }
  ],
  "authentication": ["#z6MkABC..."],
  "assertionMethod": ["#z6MkABC..."],
  "capabilityDelegation": ["#z6MkABC..."],
  "capabilityInvocation": ["#z6MkABC..."],
  "keyAgreement": ["#z6LSXYZ..."]
}
```

Each fragment is the key's own multibase value, so the method id repeats the
`publicKeyMultibase` as did:key and did:web documents do.

Multikey is the type of the signing key because
`@interop/ed25519-verification-key` exports Multikey by default and both
siblings let the suite's `export()` decide the type and context. The derived
key is different: `X25519KeyAgreementKey2020.fromEd25519()` constructs an
`X25519KeyAgreementKey2020` (its constructor sets `type` to that suite id) and
`export({ includeContext: true })` emits the
`https://w3id.org/security/suites/x25519-2020/v1` context. The suite has a
`toMultikey()` conversion but nothing in the ecosystem calls it for derived
keys, and did-method-key ships the 2020 type for the derived key. So does this
driver. A caller wanting a Multikey key
agreement method passes its own `keyAgreementKeyPair`.

Without derivation and without `keyAgreementKeyPair` the document has one key
and no `keyAgreement`, exactly as did-web-resolver's "Generating new random
keys" output minus the `id` and `controller` fields the spec removes.

Resolved (long form), the document gains `id`, `alsoKnownAs: [shortForm]` and
`controller: longForm` on each verification method. The `#z6Mk...` ids and
references stay relative. The resolved short form is the same document with
the short form as `id` and `controller` and the long form in `alsoKnownAs`.

## 8. Error handling

| condition                                   | thrown                                               |
| ------------------------------------------- | ---------------------------------------------------- |
| bad argument shape (`did` missing, both `inputDocument` and `seed`, ...) | `TypeError`                       |
| not `did:peer:`                             | `DIDResolutionError` `methodNotSupported`            |
| `did:peer:` with numalgo other than 4       | `DIDResolutionError` `methodNotSupported`            |
| fails the long-form regex, hash mismatch, bad multibase/multicodec prefix, non-object JSON | `DIDResolutionError` `invalidDid` |
| short form with no stored long form         | `DIDResolutionError` `notFound`                      |
| stored long form's short form differs from the one requested | `DIDResolutionError` `invalidDid`   |
| store `get` throws or rejects               | `DIDResolutionError` `internalError`, store error as `cause` |
| store `set` rejects in `generate()`         | `generate()` rejects with the store error as `cause`  |
| store `set` rejects in `get()` (long form)  | `DIDResolutionError` `internalError`, store error as `cause` |
| hash-valid document whose shape contextualization cannot handle (section 6.2) | `DIDResolutionError` `invalidDid` |
| long form over `MAX_LONG_FORM_LENGTH`       | `DIDResolutionError` `invalidDid`                    |
| more than one `#` in a DID URL              | `DIDResolutionError` `invalidDidUrl`                 |
| `?query` or `/path` in a DID URL            | stripped; the authority resolves (no error)          |
| fragment not in document                    | `VerificationMethodError` `notFound`                 |
| input document fails `validateInputDocument` | `TypeError` with the failing path in the message    |
| unsupported multibase header, no/multiple suites | plain `Error`, did-web-resolver messages verbatim |

`invalidDidUrl` and `internalError` are existing codes in data-integrity-core's
`IDIDResolutionErrorCode`, not new names. No `TypeError` leaves resolution:
`TypeError` is reserved for caller argument errors, and a counterparty's
document can only produce `DIDResolutionError`s.

Consumers match on `name` and `code` rather than `instanceof`, per
data-integrity-core's own guidance; `CachedResolver.resolveDID` itself uses
`instanceof` today, which is why section 5 requires a single
data-integrity-core copy. `new Error(message, { cause })` wraps JSON parse and
base58 decode failures. The codec throws `DIDResolutionError` directly rather
than a private error class, so that `CachedResolver.resolveDID` produces the
right envelope without a translation layer in the driver.

## 9. Wire-level and contract decisions

Signed off by the core contributor on 2026-11-05. Each entry records the
options that were considered and the decision taken, so a later session does
not re-propose a rejected one.

1. Verification method fragment convention for library-generated input
   documents. Decided: the key's multibase Multikey value, as returned by
   `fingerprint()` (`#z6Mk...`), with a per-entry `fragment` override via
   `verificationMethods`. This is what did-method-key and did-web-resolver
   produce. did-method-webvh does not: its `createVMID` defaults to the last 8
   characters of the multibase value and offers the full value only as an
   opt-in mode, so the ecosystem is split and this decision aligns with the
   two did-io drivers. The convention assumes the
   suite's `fingerprint()` equals its `publicKeyMultibase`, which holds for
   the Ed25519 and X25519 suites and is recorded as a precondition in
   invariant 8.
   - Rejected: `#key-0`, `#key-1` indexed in insertion order (the Python
     reference's helper). Shorter, but a different convention from the did-io
     drivers, and the index carries no information.
   - Rejected: a truncated slice of the multibase value (the spec tutorial's
     first 8 characters, did-method-webvh's last 8). Loses the self-describing
     property of the full value for a saving that does not matter next to the
     long form's own length.

2. Default `@context` and key type of generated documents: whatever the
   registered suite exports, which for `@interop/ed25519-verification-key` is
   Multikey with `https://w3id.org/security/multikey/v1`, and for the derived
   key agreement key is `X25519KeyAgreementKey2020` with the x25519-2020
   context (section 7). This is the siblings' existing convention. Noted
   because the Python reference's examples mix the 2020 types and Multikey,
   and DIDComm peers in the wild mostly send the 2020 types. A caller wanting
   2020 types throughout registers a suite that exports them.

3. Seed form: `string | Uint8Array`, strings in bnid `z1A...` multibase form.
   Copies did-web-resolver. Noted because did-method-key takes `Uint8Array`
   only.

4. Error code for a `did:peer` DID of another numalgo. Decided:
   `DIDResolutionError` `methodNotSupported`. The resolver cannot handle that
   DID at all and the envelope code tells the caller to find another resolver.
   - Rejected: `invalidDid`. Misleading, the DID may be perfectly valid.

5. References in the resolved DID document. Decided 2026-11-05: absolute in
   the driver's output, relative in the codec's. The driver resolves every
   relative id and reference against the DID (section 6.4, "Reference
   resolution"); `resolveLongForm`/`resolveShortForm` keep the spec's relative
   form so they match the Python reference content for content. The driver
   cannot stay relative because the ecosystem's verifier rejects relative
   entries: jsonld-signatures' `ControllerProofPurpose` loads the
   controller document, skips framing when `@context[0]` is the DID v1
   context (which this library's generated documents guarantee), and then
   tests `vm === verificationId || vm.id === verificationId` with the proof's
   absolute method id (`lib/purposes/ControllerProofPurpose.js:99-128`). A
   relative `authentication: ["#z6Mk..."]` never equals
   `did:peer:4...#z6Mk...`, so every Data Integrity proof and every zcap
   (`zcap/src/CapabilityProofPurpose.ts` extends the same class) signed by a
   did:peer key fails `notAuthorized`, even though the key node itself
   resolves. Framing does not rescue it either: jsonld.js frames an object
   input with `base: ''`, so `#z6Mk...` stays relative. did:key and did:web
   documents are absolute, which is what the verifiers are calibrated for.
   The size rationale was also weak: the resolved document is built in memory
   and never transmitted; only the long form is on the wire.
   - Rejected: relative references in driver output (the morning's decision).
     Fails every Data Integrity proof and zcap by a did:peer key, as above.
   - Rejected: absolute references in the codec as well. Breaks the
     content-for-content comparison with the Python reference for no consumer
     gain, since DIDComm libraries using the codec standalone handle relative
     references by spec.
   - Rejected: making only method `id`s absolute, or pushing the work onto
     consumers (section 14, do not reopen).

6. `LongFormStore` method signatures use positional parameters so that a
   `Map` satisfies them (section 6.5). No shipped store class.
   - Rejected: options-object methods plus a `MemoryLongFormStore` class. A
     `Map` already does the in-memory job.

6a. Store writes on resolution: the boolean constructor option
   `rememberOnResolve`, default `true` (section 6.5). `generate()` writes
   regardless.
   - Rejected: unconditional write-on-sight with no option. Verifiers that only
     fetch key nodes would write on every signature check and fail on store
     errors for entries they never read.
   - Rejected: default off plus an explicit `remember()` method. Breaks the
     DIDComm first-contact flow out of the box, and an application that wants
     acceptance gating can write the store itself.

6b. `MAX_LONG_FORM_LENGTH`: 4096 characters (revised from 16 KiB to match the
   `@scure/base` decode limit), exported from the barrel, not an option
   (section 6.2).
   - Rejected: 8 KiB, aligned with common HTTP header limits. A legitimate
     larger long form would resolve everywhere else and not here. The same
     objection applies to 4096, but the base58 decoder refuses anything longer
     anyway, so a larger constant would not raise the effective limit.
   - Rejected: a constructor option. No consumer has hit the limit; add the
     option when one does.

6c. DID URL `?query` and `/path`: stripped, authority resolved, fragment
   honored, matching did-web-resolver (section 6.4 step 2).
   - Rejected: `invalidDidUrl`. Honest about not dereferencing queries, but a
     DIDComm `?service=` URL would error here and resolve under did:web.

6d. Third-party-controlled methods in `generate()` path 3: a
   `verificationMethods` entry may be a bare `IVerificationMethodEntry` from
   data-integrity-core (a string DID URL reference, or a full method object
   carrying its `controller`), placed verbatim and given the default four
   purposes (sections 6.3 and 6.4). Live `{ keyPair }` entries are always
   owner-controlled.
   - Rejected: an optional `controller` field on `{ keyPair }` entries. A new
     field name where DID Core already has the shape.
   - Rejected: a `{ method, purposes }` wrapper. Same objection, and the
     default-four rule covers the first consumer; other purposes go through
     `generate({ inputDocument })`.
   - Rejected: inferring third-party control from the pair's `controller`.
     Your own other DIDs look third-party and reused pairs misclassify.

6e. Export map: `.` (codec plus driver, as the siblings) and `./codec` (codec
   only, from `src/codec.ts`), section 6.1.
   - Rejected: a single `.` export relying on `sideEffects: false`. A
     tree-shaking assumption, not a guarantee, and Node ESM does not shake.
   - Rejected: a separate codec package. Two packages to version for a
     200-line codec.

7. JSON serialization of the input document: `JSON.stringify` as-is. Key
   order is the object's insertion order and non-ASCII characters are emitted
   raw. Python's `json.dumps` escapes non-ASCII by default, so an identical
   input document containing non-ASCII text yields a different long form
   from the Python library. Resolution is unaffected (the hash is over the
   bytes the creator produced). Only independent re-derivation of the same
   DID from the same document differs, and all published vectors are ASCII.
   Decided: follow the spec text ("JSON stringify the object without
   whitespace"), do not escape, and record the interop note in the README.
   Confirmed against the Python source (`json.dumps(document,
   separators=(",", ":"))`, default `ensure_ascii=True`, no `sort_keys`).
   "Insertion order" is not quite JS's rule either, since
   `JSON.stringify` emits integer-like keys (`"1"`, `"2"`) first in ascending
   order, and floats serialize differently (`1.0` in Python, `1` in JS). None
   of this affects resolution or any published vector. Duplicate JSON keys
   parse last-wins in both JS and Python; a first-wins parser elsewhere would
   read a different document under the same DID.

## 10. Test vectors

Vectors 0 through 8 come from `decentralized-identity/did-peer-4` (README and
`tests/examples/0.json` through `5.json`) and the spec's tutorial. Vectors 9
through 11 are the three input documents that the Python
`tests/test_input_doc.py` builds and encodes without recording the result;
their long and short forms were derived for this design. All twelve were
re-derived with an independent script (`@scure/base` base58 plus
`@noble/hashes` sha256, the exact algorithm of section 3) on 2026-11-05. The
nine published ones match the README character for character. The three
derived ones could not be cross-checked against the Python library itself in
this environment; they are reproducible from the stated input documents, whose
key order follows the Python helper's insertion order (the same order that
reproduced vector 2 exactly).

The implementation stores them as fixtures under `test/fixtures/` as
`{ name, inputDocument, longForm, shortForm }` records, and both the Node and
browser suites iterate them. The twelve records in the fixture file `test/fixtures/test-vectors.json` were re-derived independently on 2026-11-05 (`@scure/base`
plus `@noble/hashes`): all twelve long and short forms match, and all pass
both regexes. The fixture file does not carry the `resolvedLongForm` and
`resolvedShortForm` fields named below: the Python reference could not be run
in the implementation environment, so the tests assert the resolved documents
property by property instead (the list below).

For each vector the tests assert:

- `encodeLongForm({ inputDocument }) === longForm`
- `encodeShortForm({ inputDocument }) === shortForm`
- `longToShort({ did: longForm }) === shortForm`
- `decode({ did: longForm })` deep-equals `inputDocument` (relative ids intact)
- `resolveLongForm` output has `id === longForm`, `alsoKnownAs` ending with
  `shortForm`, `controller === longForm` on every verification method that
  lacked one in the input, including methods embedded in relationships, and
  every other property deep-equal to the input (vectors 5 and 6 exercise
  embedded methods; vector 6's legacy `publicKey` array is left alone because
  it is not a verification relationship)
- `resolveShortForm` output has `id === shortForm`, `controller === shortForm`
  on those methods, and `alsoKnownAs` ending with `longForm`
- `driver().get({ did: longForm })` equals `resolveLongForm` output with every
  `#`-prefixed id and relationship reference rewritten to
  `${longForm}#fragment` (and the same for the short form via a store), with
  vector 3's absolute `routingKeys` entry and vector 6's `publicKey` array
  untouched

The Python README prints the resolved long and short form documents for
vectors 3 through 8. They are the expected output here as well, compared as
JSON content (property order differs: the Python contextualizer appends `id`
and `alsoKnownAs` last). The fixture file carries them under
`resolvedLongForm` and `resolvedShortForm`.

### Vector 0: README smoke test (minimal document)

Input document: `{"hello":"world"}`. The Python README encodes it with
`validate=False`, but the validation rules (section 6.3, same as Python's)
accept it anyway: it is a non-empty object with no `id` and no resources. So
`generate({ inputDocument: { hello: 'world' } })` succeeds and yields this
DID; the vector tests the codec and nothing rejects it.

```
long:  did:peer:4zQmb7xLdVY9TXx8oov5XgpGUmGELgqiAV2699s43i6Qdm3M:zQSJgiFTYiCHjQ9MktwNThRXM7a
short: did:peer:4zQmb7xLdVY9TXx8oov5XgpGUmGELgqiAV2699s43i6Qdm3M
```

Resolved long form: `{"hello":"world","id":"<long>","alsoKnownAs":["<short>"]}`.
Resolved short form: `{"hello":"world","id":"<short>","alsoKnownAs":["<long>"]}`.

### Vector 1: spec tutorial document

The spec's own tutorial input (its JSON has a trailing comma after
`"routingKeys": []`; the Python test suite's `DOC` is the corrected copy used
here).

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/x25519-2020/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "verificationMethod": [
    {
      "id": "#6LSqPZfn",
      "type": "X25519KeyAgreementKey2020",
      "publicKeyMultibase": "z6LSqPZfn9krvgXma2icTMKf2uVcYhKXsudCmPoUzqGYW24U"
    },
    {
      "id": "#6MkrCD1c",
      "type": "Ed25519VerificationKey2020",
      "publicKeyMultibase": "z6MkrCD1csqtgdj8sjrsu8jxcbeyP6m7LiK87NzhfWqio5yr"
    }
  ],
  "authentication": ["#6MkrCD1c"],
  "assertionMethod": ["#6MkrCD1c"],
  "keyAgreement": ["#6LSqPZfn"],
  "capabilityInvocation": ["#6MkrCD1c"],
  "capabilityDelegation": ["#6MkrCD1c"],
  "service": [
    {
      "id": "#didcommmessaging-0",
      "type": "DIDCommMessaging",
      "serviceEndpoint": {
        "uri": "didcomm:transport/queue",
        "accept": ["didcomm/v2"],
        "routingKeys": []
      }
    }
  ]
}
```

```
long:  did:peer:4zQmd8CpeFPci817KDsbSAKWcXAE2mjvCQSasRewvbSF54Bd:z2M1k7h4psgp4CmJcnQn2Ljp7Pz7ktsd7oBhMU3dWY5s4fhFNj17qcRTQ427C7QHNT6cQ7T3XfRh35Q2GhaNFZmWHVFq4vL7F8nm36PA9Y96DvdrUiRUaiCuXnBFrn1o7mxFZAx14JL4t8vUWpuDPwQuddVo1T8myRiVH7wdxuoYbsva5x6idEpCQydJdFjiHGCpNc2UtjzPQ8awSXkctGCnBmgkhrj5gto3D4i3EREXYq4Z8r2cWGBr2UzbSmnxW2BuYddFo9Yfm6mKjtJyLpF74ytqrF5xtf84MnGFg1hMBmh1xVx1JwjZ2BeMJs7mNS8DTZhKC7KH38EgqDtUZzfjhpjmmUfkXg2KFEA3EGbbVm1DPqQXayPYKAsYPS9AyKkcQ3fzWafLPP93UfNhtUPL8JW5pMcSV3P8v6j3vPXqnnGknNyBprD6YGUVtgLiAqDBDUF3LSxFQJCVYYtghMTv8WuSw9h1a1SRFrDQLGHE4UrkgoRvwaGWr64aM87T1eVGkP5Dt4L1AbboeK2ceLArPScrdYGTpi3BpTkLwZCdjdiFSfTy9okL1YNRARqUf2wm8DvkVGUU7u5nQA3ZMaXWJAewk6k1YUxKd7LvofGUK4YEDtoxN5vb6r1Q2godrGqaPkjfL3RoYPpDYymf9XhcgG8Kx3DZaA6cyTs24t45KxYAfeCw4wqUpCH9HbpD78TbEUr9PPAsJgXBvBj2VVsxnr7FKbK4KykGcg1W8M1JPz21Z4Y72LWgGQCmixovrkHktcTX1uNHjAvKBqVD5C7XmVfHgXCHj7djCh3vzLNuVLtEED8J1hhqsB1oCBGiuh3xXr7fZ9wUjJCQ1HYHqxLJKdYKtoCiPmgKM7etVftXkmTFETZmpM19aRyih3bao76LdpQtbw636r7a3qt8v4WfxsXJetSL8c7t24SqQBcAY89FBsbEnFNrQCMK3JEseKHVaU388ctvRD45uQfe5GndFxthj4iSDomk4uRFd1uRbywoP1tRuabHTDX42UxPjz
short: did:peer:4zQmd8CpeFPci817KDsbSAKWcXAE2mjvCQSasRewvbSF54Bd
```

### Vector 2: README `input_doc_from_keys_and_services` example (Multikey, `#key-N` fragments)

Built by the Python helper, which indexes fragments as `#key-N`. This library
uses fingerprint fragments instead (section 9 item 1), so this vector tests
the codec, not the shape `generate()` produces.

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1"
  ],
  "verificationMethod": [
    { "id": "#key-0", "type": "Multikey", "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" },
    { "id": "#key-1", "type": "Multikey", "publicKeyMultibase": "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" }
  ],
  "authentication": ["#key-0"],
  "capabilityDelegation": ["#key-0"],
  "service": [
    {
      "id": "#didcomm-0",
      "type": "DIDCommMessaging",
      "serviceEndpoint": { "uri": "didcomm:transport/queue", "accept": ["didcomm/v2"] }
    }
  ],
  "keyAgreement": ["#key-1"]
}
```

Key order above is significant (it is the Python helper's insertion order,
with `keyAgreement` last) and must be preserved in the fixture.

```
long:  did:peer:4zQmQabhRUiFPAmn7CX6B8V6qmfrs7nQQyFb6zAD7EAWvW3c:zMoDtDfb4quiz6yXy8ftBst291RGXBJaVy8FMivQWVLPbYUSAS68WgeWNxtdR5aBNraMHsPZi4iSWizFpbbZxQ2Cw56HwPxwG3SMa3wCtUkRj1LrAjcC1EE11t7vq1mggN2Y5xHTJpEbCLNnrUHG99RBb7fDEJff2YzCFqKxW4NU6tdjtw5fEy6Kz5f3KzeybV74aZY8QwWFMi3j9brksFsNhhCWyk65tKgaE2b5qyD6tLF5u3rNuEAUGNTTaJ1hPGKgCZaAAm4TdjuaSXoVaSxiXXkWjEsxRnLnqeNbw6djogDw41v2tpEawTQX7ZqL5ZbYzPi6N6L2e9Kkf4i2K2WMVLTW41n6AGmDguJPqrgkpCb71v2WiMGSsQPzk5EyPucdfQmxyn7tj4E21nZGNfY415Sp2XQZZ7yQPAimq3WrYf54srZfVjXvJBrMosCPDdm5bVKitRLjmh8ueQ3Pa8CcT3zHy8RtQRuKTQgKyWLUvMitN1eQEtaRo1vLNLYEX4cXhG51haarXRfEFyCr3FZeE9oBRWkZioCrkZTEL8rz4GAAnpPojxCPXsecE1WJXkcqZw1bS9YwU5gugNybPAFpoc2AhwtcQNvj9UhaZisVvPiEsynRG2cmwyjqi5dD8b6FvwCMUq8FzkpyV2UR8ePMMt3Co8FofVvKCkU4a4CRWF6hWCrEQqpSC5abNscuvpcMUfzvSVNrFVZyCiSMX2Wwa7tnxvujZTjutKXr
short: did:peer:4zQmQabhRUiFPAmn7CX6B8V6qmfrs7nQQyFb6zAD7EAWvW3c
```

### Vector 3: examples/0.json (2018 key, did-communication service)

```json
{
  "@context": "https://w3id.org/did/v1",
  "verificationMethod": [
    { "id": "#1", "type": "Ed25519VerificationKey2018", "publicKeyBase58": "AU2FFjtkVzjFuirgWieqGGqtNrAZWS9LDuB8TDp6EUrG" }
  ],
  "authentication": ["#1"],
  "service": [
    {
      "id": "#didcomm",
      "type": "did-communication",
      "priority": 0,
      "recipientKeys": ["#1"],
      "routingKeys": ["did:key:z6Mknq3MqipEt9hJegs6J9V7tiLa6T5H5rX3fFCXksJKTuv7#z6Mknq3MqipEt9hJegs6J9V7tiLa6T5H5rX3fFCXksJKTuv7"],
      "serviceEndpoint": "http://bob:3000"
    }
  ]
}
```

```
long:  did:peer:4zQmQ4dEtoGcivpiH6gtWwhWJY2ENVWuZifb62uzR76HGPPw:z7p4QX8zEXt2sMjv1Tqq8Lv8Nx8oGo2uRczBe21vyfMhQzsWDnwGmjriYfUX75WDq622czcdHjWGhh2VTbzKhLXUjY8Ma7g64dKAVcy8SaxN5QVdjwpXgD7htKCgCjah8jHEzyBZFrtdfTHiVXfSUz1BiURQf1Z3NfxW5cWYsvDJVvQzVmdHb8ekzCnvxCqL2UV1v9SBb1DsU66N3PCp9HVpSrqUJQyFU2Ddc8bb6u8SJfBU1nyCkNMgfA1zAyKnSBrzZWyyNzAm9oBV36qjC1Qjfcpq4FBnGr7foh5sLXppBwu2ES8U2nxdGrQzAbN47DKBoKJqPVxNh5tTuBdYjDGt7PcvZQjHQGNXXuhJctM5besZci2saGefCHzoZ87vSsFuKq6oXEsW512eadiNZWjHSdG9J4ToMEMK9WT66vGGLFdZszB3xhdFqEDnAMcpnoFUL5WN243aH6492jPC2Zjdi1BvHC1J8bUuvyihAKXF3WmFz7gJWmh6MrTEWNqb17K6tqbyXjFmfnS2RbAi8xBFj3sSsXkSs6TRTXAZD9DenYaQq4RMa2Kqh6VKGvkXAjVHKcPh9Ncpt6rU9ZYttNHbDJFgahwB8KisVBK8FBpG
short: did:peer:4zQmQ4dEtoGcivpiH6gtWwhWJY2ENVWuZifb62uzR76HGPPw
```

Expected resolved long form (from the README; note the property order, which
is the Python contextualizer's and is not something this library needs to
reproduce, only the content):

```json
{
  "@context": "https://w3id.org/did/v1",
  "verificationMethod": [
    {
      "id": "#1",
      "type": "Ed25519VerificationKey2018",
      "publicKeyBase58": "AU2FFjtkVzjFuirgWieqGGqtNrAZWS9LDuB8TDp6EUrG",
      "controller": "<long>"
    }
  ],
  "service": [ ...unchanged... ],
  "authentication": ["#1"],
  "alsoKnownAs": ["<short>"],
  "id": "<long>"
}
```

### Vector 4: examples/1.json (2018 key, http endpoint)

```json
{
  "@context": "https://w3id.org/did/v1",
  "verificationMethod": [
    { "id": "#1", "type": "Ed25519VerificationKey2018", "publicKeyBase58": "3dtu2WWtd5ELwRTJEPzmEJUYEp8Qq36N2QA24g9tFXK9" }
  ],
  "authentication": ["#1"],
  "service": [
    {
      "id": "#didcomm",
      "type": "did-communication",
      "recipientKeys": ["#1"],
      "serviceEndpoint": "http://172.17.0.1:9031/a2a/5b6dyY6PndLaCnWxZbeEYW/5b6dyY6PndLaCnWxZbeEYW/2f6aae0c-6b04-40ff-a25e-faecaea39f83"
    }
  ]
}
```

```
long:  did:peer:4zQmRMVzDUXhV64pfw3vFaDvyExjzW9oBXCF2n4zYCaHQFAT:zMx3zwMnDECV3GiFs8nmHr38TziMEEkcgFBEDH5PXQ8hxnMrwNfB9wTwskpJMjggeg8NF1jeDSK5772op2zLLdy8TGFCEiYQxpUvvku8qSCZx5Q8V9Li9mDp6WEqGabXLQ9GTinmyQHQyJ6TcfbHaTtJUFjHS962LFPdUwv3aDK673Pci2doTyHVTAsw4m5eToS2dKbtix9f7HNxwvixnbQucWNAWVAF6HTxFYRYmrRPDmeE8n7V1fXFkY7yvR6BWxKiWwHd8Vb1TbBBRStf5niRM2dUAyjJorTstPWSfG2pN5DsRF81NUd7Aif4EhNAQEJCTuAHxQ3rCnNkb9Pf7YTTxbt1t25YgDMioDi4uFhYcnTbHj7D74yNPC2Cfk6WasU69hMxj7Wxro58vtkA6hvDWGtnDyX4PzntBp3fn62R25HW2jadsZMiJpm5ufpYSktEFEHX6gGeF4KPgyU8b2hhyS3FKL4DULYLB6d6CZqUpwrJesGfDtFjfG1btbdmjd6Lm7FCbL3fU9E3AJWEmnFkg16vARiQ1CrzeS9SyNtybKCk4
short: did:peer:4zQmRMVzDUXhV64pfw3vFaDvyExjzW9oBXCF2n4zYCaHQFAT
```

### Vector 5: examples/2.json (embedded verification methods, no `verificationMethod` array)

Exercises contextualization of methods embedded directly in `authentication`
and `keyAgreement`.

```json
{
  "@context": "https://w3id.org/did/v1",
  "authentication": [
    { "id": "#key-1", "type": "Ed25519VerificationKey2020", "publicKeyMultibase": "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V" },
    { "id": "#key-2", "type": "Ed25519VerificationKey2020", "publicKeyMultibase": "z6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg" }
  ],
  "keyAgreement": [
    { "id": "#key-3", "type": "X25519KeyAgreementKey2020", "publicKeyMultibase": "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" }
  ],
  "service": [
    {
      "id": "#didcommmessaging-0",
      "type": "DIDCommMessaging",
      "serviceEndpoint": {
        "uri": "https://example.com/endpoint",
        "routingKeys": ["did:example:somemediator#somekey"],
        "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
      }
    }
  ]
}
```

```
long:  did:peer:4zQmSAu6N2xECXwbofFMA2ZgeL3EERDPNrG5XQGnaA528mzL:zAPouDipG3F4FgNtQyjLFKAaesTzXDKDm71QEEUJdxQjZ94nyzBR7SKPQ5woVNc16Yqn6yrVEaFAZTWoJKgjz6Jc9ACCvEBmCB9D1kYGCnzB4Cx65SHfsX4c65XezdJyDzBNBZhprZtmqWFFv8dX177Yzqq9pBJkjSXJvKsrpXAsMG8EKMTFFosrrFoyH9jDy9m3pUHHGgZvXD1xUejiehoR5wQsjhw3PWQSYobgGMZP7Q3YNxSwRQ4ThLQLFUVbruqK4PTRiYahi8Ym73Kyg3r7krbo8VUMfU31hsX3iTBgfGuf27Ce7ibHhdJY5d7CDBjLwrxJV5zruQR6k8bYzi5JyfR1VFYq8njUvbQkfWSjtd71fZUpmffkUr5zkAS9gw2AwYp12MsWQL2Ebw25YnyWxLs3wCyEG4MuinjA81T3V91Uv3SxHTe2Tww61nf4QSA2xh81wZaxiCrD4VuEM1DsJsu2qxatv5sfiA3CuFqtABYKx59e61G2pzCpDpcMdRaXJ1tZkZ3j7L42mEuicf7NWqg6FgyU4aT4NTzCRRGkUEcrKATT1NUAYkqpYYau8VXzdRcNWfSPY8PJLXjQQhnxAdb6oSdk2srg75ZzqYNSHU7TqhUCUTPTd8jJT9cXihqHrwTp1toeZAhf6Uyy8myALYpqrTaDQS3VULWR8QA4fuqjtRPRsjXSMaNLxYYCEksXbMVY7kNSJ4Xyr8DpDzrGZRFaCELWYuRYzjQpmGTWVrea2ZbwsirxpjKJ99t5aQ8mdSvDZZP8GskdFABXb1kJPb18JnqS4EzFPmUyLPJuzYaGMhFGbJt214iZZLUSzsp6wL1kvfg789DavkM2QiYgCYPb1kCDjtGbqGge7L4Vt2GRJGc2r39r2Trypi6VDvA8z2UcGm5d1mk4gwd15xx
short: did:peer:4zQmSAu6N2xECXwbofFMA2ZgeL3EERDPNrG5XQGnaA528mzL
```

### Vector 6: examples/3.json (legacy `publicKey` array, embedded keyAgreement, 2019 X25519)

Exercises the rule that `publicKey` is not a verification relationship and
is left uncontextualized, while the embedded `keyAgreement` method gains a
`controller`.

```json
{
  "@context": ["https://w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2018/v1"],
  "publicKey": [
    { "id": "#z6MkrmNwty5ajKtFqc1U48oL2MMLjWjartwc5sf2AihZwXDN", "type": "Ed25519VerificationKey2018", "publicKeyBase58": "DK7uJiq9PnPnj7AmNZqVBFoLuwTjT1hFPrk6LSjZ2JRz" }
  ],
  "authentication": ["#z6MkrmNwty5ajKtFqc1U48oL2MMLjWjartwc5sf2AihZwXDN"],
  "assertionMethod": ["#z6MkrmNwty5ajKtFqc1U48oL2MMLjWjartwc5sf2AihZwXDN"],
  "capabilityDelegation": ["#z6MkrmNwty5ajKtFqc1U48oL2MMLjWjartwc5sf2AihZwXDN"],
  "capabilityInvocation": ["#z6MkrmNwty5ajKtFqc1U48oL2MMLjWjartwc5sf2AihZwXDN"],
  "keyAgreement": [
    { "id": "#zC8GybikEfyNaausDA4mkT4egP7SNLx2T1d1kujLQbcP6h", "type": "X25519KeyAgreementKey2019", "publicKeyBase58": "CaSHXEvLKS6SfN9aBfkVGBpp15jSnaHazqHgLHp8KZ3Y" }
  ]
}
```

```
long:  did:peer:4zQmTtzjstZ5p2Li62vbqPTgHBbdQM7QE5BvcKAme4t3HHPU:z2EH35ZPdC1CKXQ9hyy8oW5Jst9UVnvgwDSLyCzCK2V8zMDsKe2RD8n7GRtE25KJyYcCM4vrahEMfEVpEcAVFZrecQc8suE6SX5fAc581n8DBiifrA94GtsC1gsgLxoNMgbpNzm2Ezys92DvCgDdtT83FZj99jRQnB7fgApfd98GniT7vtyMY27QuVETYgBReAxM3KkruT4pcJXK5Co5F273u4kYzVh6kjZnjZdjJiQbzPQEBq2VwdLft1uZbEfSEbZsvpkR4nQLowGfhSvWUK8gyDHFFPtdUCqV8k2qL7VqK7KweWiEn1DZbSkVV6LV3FBi9hdKEoVu64p4JofiDWy4WgGLtPmEdVVn2C7n2n5Qpfouha4PX3BpBDWiUFXeoWeEthtpBbtdujEXpN5DnqhBNLwgQMFg3ec9cHGai2PCcFtnkLpSjEeGnTnfQAiUEowneupmC39zqRxaHgnd9gSFGPjyJ5yUwsBuWdvbYyv4xMNf5wN32pzgQuHw56hnA6xqpccqhkZxPPmjN4Kf3muRmragcTMgAGvgpUPuLpiUnoqXW6gHqohKs19thSzEAxtCYVahQ3hZPdSYBQKBo5gJVxULyL2DAaWkEzkrrbpVzA2fZ52CJm7JcWcn75Aenf49SdTgXRaYf8dKFN5t1UqsuSWhkoJmiziYMrRYQZkRFizGxs6p8HrfWmqQeq9DhC2mLd6TXQkAxYpaW28RB7xXaGwPRpFpCfeaZAFwSNfzSoT8Kee52Sow5UMANTN9FfNzPJYeQBrBq6GGN6ayLm3KJbqQeZrRcuomYy58pqJ71P1JwymdDVNMe328EMD6UczfJPnTDPH3DeenJwTSdDRuDStJDAn3BWujigjJVAHMnXeMcG63obbFMc4XTsSt9W8bKTs72CpffzB6RsZQyL5UooRBGEj1Y5xHhYjdQAtE6uix2Xg5Dp3NPwUirQ8UsU2Sw95bYr8GZFr6dAHwo8pcmF9WNWihnWMEnbzFnBZqVNAUJ6G
short: did:peer:4zQmTtzjstZ5p2Li62vbqPTgHBbdQM7QE5BvcKAme4t3HHPU
```

### Vector 7: examples/4.json (JWK material, `type` before `id` in the method)

Exercises key-order preservation inside a nested object: the method lists
`type`, `publicKeyJwk`, then `id`.

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "verificationMethod": [
    {
      "type": "Ed25519VerificationKey2018",
      "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "UTBElpNSZB8dS_R9rzWnWB-ozdtL7Sz96RQZhwnzur8" },
      "id": "#z6MkjvBkt8ETnxXGBFPSGgYKb43q7oNHLX8BiYSPcXVG6gY6"
    }
  ],
  "authentication": ["#z6MkjvBkt8ETnxXGBFPSGgYKb43q7oNHLX8BiYSPcXVG6gY6"],
  "assertionMethod": ["#z6MkjvBkt8ETnxXGBFPSGgYKb43q7oNHLX8BiYSPcXVG6gY6"]
}
```

```
long:  did:peer:4zQmb5cH6UdXeQze2CkPM1FjLP3Yi6SHPHQKPq5wjeS3YiUt:z3AFKXqX5u3s7opYvAJuaLXm4vjXWp67LDGCq83dHQJ9KRRDdPYyAwMA2CXmbFT12ZFD8iAKrd9pdbERrB7KyyAvQ2fikaprHyV8ekiys1DfCd7VTWhM5zNfZY9grWGC8qvJ4qguDNaHwrvwFoWz3gEP52kt1KiY7WAgUvzkck1ikaQNDT21rSomYWLYDovJUkbvnnV13RRbbcz8GJWT5cRnacvVcXrGVTTZHiUcgw2yma2t9T1dBExetW73cobAmrAH2kU2ZsazkbMxchMen2Jf327E9AckTHt7CGcDKU2HZ442v6cRhr76LXxbmEnXqDQ92fjuZ7iPEJhVCWF6XRB2ZvMkoh6i5Gt3T9fP4cznKXLCJ8ucbE62Kp4fqMpdNs8yd6wWmr4hzxeJnN8qV1xNJ5oCF8KvV8DeRTXmcs2nfk7BTV8AijCf1CEoLvTtFWEkG7XrK3dJH1r4hJPfUAEiX17GXFyRdz4NjdKV4XHFsmYEAkwW1NJzDVoJtWdnjMRj4F2obmEkBHD6F8uPhef7RGs8HHM6Lc1XTz6g
short: did:peer:4zQmb5cH6UdXeQze2CkPM1FjLP3Yi6SHPHQKPq5wjeS3YiUt
```

### Vector 8: examples/5.json (JsonWebKey2020 secp256k1, empty `service` array, relationships before `verificationMethod`)

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
  "authentication": ["#key-1"],
  "service": [],
  "assertionMethod": ["#key-1"],
  "verificationMethod": [
    {
      "id": "#key-1",
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "secp256k1",
        "x": "masUHNuJ0oH0C_e5rLUu5VKwmU2l-a7rrNTqA__afN8",
        "y": "UmGGX_WgRFXbw6qTli9xcQ0owtkZVuUGVyM23e8rZe8",
        "kid": "#keys-1"
      }
    }
  ]
}
```

```
long:  did:peer:4zQmYxyxu3ndxss6ZopgaRN7xfqrXVpUbLqJ5Qd9x8ov2HMo:z2LBoAcpyFY24cFmhR6v5E4cenhVk9os2NAz6b61FgJzvZTgjEncziY6EXJYv4hjHzke9AkCawZszR8QFYjHdf9xRk2qpqZN7tgkudQBTuZ7QNmmsfdJ9U6g2fcpoGqnqnKc3iqGqUXWWuUG4Y7wPVxFrkLAPA7jUDz6UFsLTcJ5vX5jVtdYeRBvKcMDH1pyKNSGQFzYAmXH5dnJTr6MTHf71RDicGZU2MkuLfUGzUJXHE3QEa5WJqE1WmF8mU5tUVr1ysKHxck97JdU35RBR96FG2UXqLSYcaALJZYXTRtu5q8ucwc5bb16T9sD2H4A3kZeStPs6zbHqq3uxM4En2ZwSjsRSgF8Fowkd6FpQpSRpf8MdmPchS5BZgSWTLmP2Z6T5vkgnab6KZgYsv4qvjBw9twBRBLdWRH7XeLAugb4jiEKwA3hMhmZeunGvUVbS4Q4rZ5FxW7mob2SYb7ncbDpsAMV2qFwMoua1ybbcwE1r1HYCCziLrmfe17GyNpwBdVhjdKvdwRxJFQPyHJon
short: did:peer:4zQmYxyxu3ndxss6ZopgaRN7xfqrXVpUbLqJ5Qd9x8ov2HMo
```

### Vector 9: test_input_doc.py `test_input_doc_generation` (derived)

The document the Python helper builds from two `KeySpec`s with default
identifiers plus one service. The Python test only asserts that `encode()`
succeeds; the forms below were derived for this design. Note the key order:
the helper appends `service` while processing the first key, so it lands
between `authentication` and `keyAgreement`.

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
  "verificationMethod": [
    { "id": "#key-0", "type": "Multikey", "publicKeyMultibase": "z6MkrCD1csqtgdj8sjrsu8jxcbeyP6m7LiK87NzhfWqio5yr" },
    { "id": "#key-1", "type": "Multikey", "publicKeyMultibase": "z6LSqPZfn9krvgXma2icTMKf2uVcYhKXsudCmPoUzqGYW24U" }
  ],
  "authentication": ["#key-0"],
  "service": [
    {
      "id": "#didcommmessaging-0",
      "type": "DIDCommMessaging",
      "serviceEndpoint": { "uri": "didcomm:transport/queue", "accept": ["didcomm/v2"] }
    }
  ],
  "keyAgreement": ["#key-1"]
}
```

```
long:  did:peer:4zQmTv3KWcX57BNEZv7QokUMX2cwApxhAvoMi2ZL847X54rs:zCiAzURMU5zn9G3QagGHu33WoYmuKooZRnT5mhqFFsLSKysJ5oXZ6nsmEzxnZkLwGSH5kHpSAZNvUrJ8ku22mCGKcDCMbEb8zwYkvRfii1czBt8wZbk57SjQsfrCYmx9uLfG9AyZ5HQg6UGn618Gn9G4hA19tWTvYnvsR1Wx9tNyS44ZXehVo7E3NDH4r3ijsJmAyT3aD5bESxzWpn2yR5GvVqopogSWYSV84zxsVntd4iw4g28E769QjCqwxFCJopjF6m4ZmezVsUtHsyN4WsxTJPMi62pmoAy5ZEwayjAzAsVykjJr6jwM7sux7t41G7sMDm2kgdSdy4BPHBWkkjAVar4pHqQN4iDecXMGitLMcc3wsUke3Fre86Z3eqwtqFkTX1x8kAgtWB6TLJQk9TDJiPabQRTnZ4jVq1B5cSPY7mxJtLDnsRPZeymGsKa4KcGhnGzJweoznZXiGj5PWXbEVDpWrCUDVRd3cNtZM5nJWgggywF4WLZmqPwBYyizLZkAz716Q8nXRRVD2kgapMFmX9ekFHhYmEEMdCWdBCzh1c51XcYtpUcDYix7MLvYjynXxizn5h8fn3KVdkVniGpthqtqSqJvYFJhGkFGV2MLW5Ee9wpwi5JMadHwVg2F5hNjfi7JjT3dFFEUhwWMmknMXLyBi9YqkmihAEi25zKBzpCWAdy79x7cWtkChHEVCKUEui
short: did:peer:4zQmTv3KWcX57BNEZv7QokUMX2cwApxhAvoMi2ZL847X54rs
```

### Vector 10: test_input_doc.py `test_input_doc_generation_extra_params` (derived)

Custom identifiers (`#auth-0`, `#agree-0`) on the first two keys, a third key
with no relationships that falls back to the indexed `#key-2`, and the same
service. Exercises a verification method referenced by no relationship.

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
  "verificationMethod": [
    { "id": "#auth-0", "type": "Multikey", "publicKeyMultibase": "z6MkrCD1csqtgdj8sjrsu8jxcbeyP6m7LiK87NzhfWqio5yr" },
    { "id": "#agree-0", "type": "Multikey", "publicKeyMultibase": "z6LSqPZfn9krvgXma2icTMKf2uVcYhKXsudCmPoUzqGYW24U" },
    { "id": "#key-2", "type": "Multikey", "publicKeyMultibase": "z6Mkq4o8kZj1nK5z5Y8K8gY7aV9j8jg6YJzqZ6Dj9j7eY4d2" }
  ],
  "authentication": ["#auth-0"],
  "service": [
    {
      "id": "#didcommmessaging-0",
      "type": "DIDCommMessaging",
      "serviceEndpoint": { "uri": "didcomm:transport/queue", "accept": ["didcomm/v2"] }
    }
  ],
  "keyAgreement": ["#agree-0"]
}
```

```
long:  did:peer:4zQmcL91xYEocrBQXuvecsdcpoqK2wD6SugHUrUXSpc4tGXd:zAhppojSkLYLoSMLTJqkh43dwEtTJPcfdtqUvV4bFGsmDAxYCQ8tZMMafaFDuC56pxy3FtHBkoJVLgx8b6gVa2vHv36HVh2wmH9zNFVoNj3PgtG7zLqJLMNbJ42iDYRh6K2Lh4kEbA8DpyTSwgrVwMTmFvY5vUV1hjESxWfeTSvhfm8hCYeKBLbd7dnxLpnLpUGUHRq3B6sSVsmw9hdyFuQfLcRPULtAQHJpAUqpi9dEGKRMnvAFZDr34UfCRejjkXuufN3k2d6qpqebG7EHKjQkEWj8QiiQ7FJQR4Czg5VMY4DXK52UP6r8Bq2JigYWHjj4xSk1EQVz4dbSXVud2bWKgBeNmMy9Seuuv4qjvY6xPLgEu4MPz2q5k2HEH71Er2AZ2xF5WPo6NKzJDiqkoVyBcuBx4anJR3aF1jF1cF3sVLQXvvaozRajQe9aym1s1fTgYZScRPvEZ8rySz5zi1b5L6nWsxeUqzdyWSLXbWtYQFQ7RbKmByFn9KTnVb2bror9PdCjM2ihvjJu3oPRTe7SHrgogUxf2CgMvLLP8kXbAP1Mt3KbRjHoPufqYQ5w5UFczacc9jk1A7VRzxAGiY46iLmc2kL2Z7qMVNam9pSxGs9pkMa38TR1FBM6n6KixgazstzQ9syrkVkQSSxeMKQ2Qyb3PbDRR5qeXHthv7fwMhhaDbHsZ6UXAegpNtPWvf2w7JxmeFXDR4XRbxGj4jFVq5R9y2SfVh34MUmdAFnodL2b7TNAS8Rkk8HvtNqCasg4oKT3ntaLV3c1VFWS8dtwTSfpJbjtWBRwUMY3867LSzYDSh4q2b3o5cUTMsVogmi7oQF17iKczHBNtPcY7jAkWL9X3iU
short: did:peer:4zQmcL91xYEocrBQXuvecsdcpoqK2wD6SugHUrUXSpc4tGXd
```

### Vector 11: test_input_doc.py `test_input_doc_generation_jwk` (derived)

Two `JsonWebKey2020` methods with the jws-2020 context. The JWK `x` values are
placeholders in the Python test (the multibase strings reused as-is, the test
itself says "Not real"), which does not matter to the codec.

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
  "verificationMethod": [
    {
      "id": "#key-0",
      "type": "JsonWebKey2020",
      "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "z6MkrCD1csqtgdj8sjrsu8jxcbeyP6m7LiK87NzhfWqio5yr" }
    },
    {
      "id": "#key-1",
      "type": "JsonWebKey2020",
      "publicKeyJwk": { "kty": "OKP", "crv": "X25519", "x": "z6LSqPZfn9krvgXma2icTMKf2uVcYhKXsudCmPoUzqGYW24U" }
    }
  ],
  "authentication": ["#key-0"],
  "service": [
    {
      "id": "#didcommmessaging-0",
      "type": "DIDCommMessaging",
      "serviceEndpoint": { "uri": "didcomm:transport/queue", "accept": ["didcomm/v2"] }
    }
  ],
  "keyAgreement": ["#key-1"]
}
```

```
long:  did:peer:4zQmbLiJT4rSAFW6QegZFT5ZJuFDjStb8nuLoFVkvHZoKp1r:zFs1KPrzpZpD8aUqFhESnaTxBpMJTu6pV4y8VLCpuBYG4QhpjvAVm6vQV4Q6cgQid7iqyjePvjwWxD1cEBynHMbgd6fNLNRuKeQBAU49vpqwDnwnDyAUZkcxwhfrKJgc23v419yauwQXLb8XVa4ThiJujZq9pB3h4vNx8qZywrwXXjRBPvbDkAvZbdzQe8gmMtLViLFt7y3vFK6QCYqSch5cdqXvpYftQYR4FTjSDkAwxPzvetXTNSsRRrgHAHzqZDGaWfSSKKXwNaokWKbeK8xHMQVmiHN5wfCsKs9JFHKM73SLBs4sPYSZv8NT2EGfGwYD5yXJ5iNkenmmdVMwgjAwp387K94qw1uHXfWC8bcA2i4wR2yCm1Sf6KQ7vyjB8MjYiKuDtWcVsg61utgXn132tC69Jkv6nm4Et69ubJz6icL8hPHREXkMgaxTdyaYhEqiY8FEfB9A1NVun3fawsdBAnVS1LQhuxj95FXdhHsWZXLL9A93vMhkeVimE4BPV5qyFjRxYTmCk7DWUQeTMwhxE9hxkbzjH6okHz8s6iQH84wdrDrzpAuR2qt5pDXY26827jv4remFZn46McBDLCWrvM1Vo4EextDLE4eLQPcLwe8ZwvLbFXamMKQcL65XHcHHB64guLSFbaRxtba3aEBwqF5qdDPvXpWdchWzLw82CzszWovAWhbVMtFcjNLmti9WHAPCGy7uZtYaq4uX76qKUYMuBus7bdJuLU9grqEDdJj8CQ6Uv1m1Tk5beMDT669PNMg7BeLMN2Ae7aCwE1EXYCyVnMu5bhJMA5Qae9a
short: did:peer:4zQmbLiJT4rSAFW6QegZFT5ZJuFDjStb8nuLoFVkvHZoKp1r
```

### Validation cases from test_valid.py

Not DID vectors, but the Python suite's table of invalid input documents is
ported as-is to the `validateInputDocument` tests: `0`, `{}`, a document
with a root `id`, `alsoKnownAs` as a string, and, for each of the seven array
properties, the values `"not a list"`, `[{}]`, `[{"id": "did:peer:4:...#key-1"}]`
(absolute id), `[{"id": "#key-1"}]` (no `type`), and `[{"id": 0}]`. All six
`examples/*.json` documents must pass validation.

### Deterministic generation fixture

did-web-resolver's README documents that the seed
`z1AhV1bADy7RepJ64mvH7Kk7htFNGc7EA1WA5nGzLSTWc6o` yields the Ed25519 key
`z6MkmDMjfkjs9XPCN1LfoQQRHz1mJ8PEdiVYC66XKhj3wGyB`. The same seed through
this driver's `generate({ seed })` must produce an input document whose single
verification method has id `#z6MkmDMjfkjs9XPCN1LfoQQRHz1mJ8PEdiVYC66XKhj3wGyB`
and that `publicKeyMultibase`. The resulting long form is recorded as a
fixture once the implementation first produces it, so the generation path is
pinned, not just the codec.

## 11. Test plan

Node (`test/node/`) and browser (`test/browser/`) suites, the browser one
mirroring the Node one through the existing Playwright plus Vite harness.

Codec (`numalgo4.test.ts`):

- Every vector in section 10, all assertions listed there.
- Tampered hash (flip one character of the hash portion) throws
  `DIDResolutionError` `invalidDid`.
- Tampered document (flip one character of the encoded portion) throws
  `invalidDid`.
- Short form passed to `decode` throws `invalidDid` with the "cannot decode a
  short form" message.
- `did:peer:2.Ez...` and `did:peer:0z...` are rejected by the regex guards.
- Wrong multibase prefix (`m...`) and wrong multicodec prefix after decoding
  throw `invalidDid`.
- Contextualization does not mutate the caller's input document, checked by
  deep equality on nested method objects and the `alsoKnownAs` array, and by
  resolving the same decoded document as long form and then as short form.
- `alsoKnownAs` already present in the input is appended to, not replaced,
  and the appended form is the last entry.
- An embedded method that already carries a `controller` keeps it, including
  `controller: null`.
- Hash-valid hostile shapes each throw `invalidDid` rather than a bare
  `TypeError`: payloads `null`, `[]`, `"str"`, `5`; `alsoKnownAs` as a
  string, `null` and `{}`; `verificationMethod` as a string; a `null`, number
  and array entry in a relationship; a relationship given as a single object.
- Boundary payloads `{}` (encodes to exactly 6 base58 characters, passes) and
  `0` (4 characters, fails the regex as `invalidDid`).
- A long form one character over `MAX_LONG_FORM_LENGTH` is `invalidDid`
  before any decoding.
- A decoded document with an own `__proto__` key resolves without altering the
  result's prototype.
- A root `id` in the input is overwritten on resolution.

Input document (`inputDocument.test.ts`):

- Each `validateInputDocument` rule has a failing case with the expected
  message path (`authentication[1]: resource id must be relative`), including
  the uniqueness rule (same key twice, two entries with one `fragment`).
- `{ hello: 'world' }` passes validation.
- `addVerificationMethod` with a default and an overridden fragment; context
  de-duplication; `controller` and absolute `id` stripped from the exported
  node; the derived X25519 node has an `id` and the x25519-2020 context lands
  in `@context`.

Driver (`DidPeerDriver.test.ts`):

- `generate()` with no arguments, with the Ed25519 suite registered: one
  Multikey method whose fragment equals its `publicKeyMultibase`, four
  purposes, `didDocument.id` is a valid long form, `alsoKnownAs[0]` is its
  short form, `keyPairs` keyed by `${longForm}#${fingerprint}` while the
  document's method id is the relative `#${fingerprint}`, `methodFor({
  purpose: 'authentication' })` returns the live pair with `controller` and
  `id` set, `methodFor({ purpose: 'keyAgreement' })` throws.
- Same with `enableEncryptionKeyDerivation: true`: a `#z6LS...`
  `X25519KeyAgreementKey2020` method under `keyAgreement`, the x25519-2020
  context in `@context`, `methodFor({ purpose: 'keyAgreement' })` returns it.
- Every `TypeError` combination in the section 6.4 path rules: `keyPairs`
  without `inputDocument`, `seed` with `verificationKeyPair`, `keyType` with
  `verificationKeyPair`, a `keyPairs` fragment absent from the document, a
  `keyPairs` pair whose public key differs from the document's method.
- `generate({ inputDocument, keyPairs })` with a partial map: `methodFor` for
  the unbound method throws; with an embedded method: `methodFor` returns the
  bound pair.
- `fromKeyPair` with a plain `IKeyPair` description; with only
  `keyAgreementKeyPair`. `publicKeyToDidDoc` with an X25519 description puts
  it under `keyAgreement` and does not write the store.
- Store failure injection: a store whose `set` rejects makes `generate()`
  reject; a store whose `get` rejects makes the short-form `get` fail
  `internalError`, not `notFound`; a store returning a non-string is a miss;
  a store returning a valid long form of a different DID is `invalidDid`; an
  async (promise-returning) store, `generate()` then an immediate short-form
  `get` hits; `generate({ seed })` twice writes the same entry.
- `get({ did: 'did:peer:4...?service=didcomm#z6Mk...' })` returns the key
  node and `get({ did: 'did:peer:4...:z.../path' })` returns the document;
  `get({ did: 'did:peer:4...#a#b' })` is `invalidDidUrl`; `did:peer:` with no
  digit and `did:peer:4` with garbage are `invalidDid`; `did#` resolves the
  document.
- `get({ url })` for a fragment shared by a method and a service returns the
  method; for a key in a legacy `publicKey` array is `notFound`; for a type
  outside the context table in a document without `@context` returns a node
  without `@context`.
- `generate({ verificationMethods: [{ keyPair, fragment: 'key-1' }] })`
  honours the override.
- `generate({ verificationMethods: ['did:key:z6Mk...#z6Mk...'] })` appends the
  string to the four default purposes and adds nothing to
  `verificationMethod`; a full method object with `controller: 'did:key:...'`
  lands under `verificationMethod` with that controller intact and
  `methodFor()` for it throws; an object with an absolute `id` is a
  `TypeError` from validation.
- `generate({ seed })` is deterministic across two calls and matches the
  did-web fixture key.
- `generate({ keyAgreementKeyPair })`, `generate({ verificationMethods,
  service })`, `generate({ inputDocument })`, `generate({ inputDocument,
  keyPairs })`.
- `generate({ inputDocument, seed })` is a `TypeError`.
- No suite / multiple suites / suite without `generate` messages.
- `fromKeyPair()` and `publicKeyToDidDoc()` round-trips.
- `get({ did: longForm })` equals `resolveLongForm`; `get({ url:
  methodFor({ purpose: 'authentication' }).id })` returns the node with an
  absolute `id`, `controller` and `@context`, while the document returned by
  `get({ did })` still carries the relative id.
- `get({ did: shortForm })` without a store is `notFound`; with a `Map` store
  after a long-form `get` it resolves with `id === shortForm`; with
  `rememberOnResolve: false` the long-form `get` leaves the store empty and
  the short form stays `notFound`, while `generate()` still writes.
- `get({ did: 'did:peer:2...' })` is `methodNotSupported`; `get({ did:
  'did:key:...' })` is `methodNotSupported`.
- Unknown fragment is `VerificationMethodError` `notFound`.
- `publicMethodFor` for each default purpose.

did-io integration:

- `CachedResolver.use(driver)`; `resolver.get({ did })`, `resolver.get({ url
  })`, `resolver.resolveDID({ did })` envelope for a long form, a short form
  miss (`notFound`), and a `did:peer:2` (`methodNotSupported`);
  `resolver.generate({ method: 'peer' })`.
- Short-form `notFound`, then a long-form `get`, then the short form again,
  all within the cache TTL, resolves.

End to end (the test that would have caught the relative-reference failure,
and the one that pins section 9 item 5): sign with the
`authentication` key from `generate()` using `@interop/ed25519-signature` and
verify through jsonld-signatures' `ControllerProofPurpose` for
`authentication` and `assertionMethod`, with a documentLoader built on
`CachedResolver` plus this driver; then delegate and invoke a zcap whose
`controller` is the did:peer DID and verify it. Both in Node; the browser
suite repeats the signature case.

## 12. Glossary (seed for ARCHITECTURE.md)

- **Input document** -- the id-less, relative-reference document a did:peer
  numalgo 4 DID is derived from. Lives in `src/inputDocument.ts` for building
  and validation. Avoid: genesis document, source document, DID doc template.
- **Encoded document** -- the multibase base58btc string of the
  multicodec-json-prefixed input document bytes; the part of a long form after
  the second `:`. Avoid: payload, blob.
- **Long form** -- `did:peer:4{hash}:{encoded document}`. Self-resolving.
  Avoid: full DID, expanded DID.
- **Short form** -- `did:peer:4{hash}`. Resolvable only through a stored long
  form. Avoid: hashed DID, compact DID.
- **Contextualize** -- the spec's term for adding `id`, `alsoKnownAs` and
  missing `controller`s to a decoded input document. It does not touch
  relative references; that is reference resolution. Lives in
  `src/numalgo4.ts`. Avoid: hydrate, expand, materialize.
- **Reference resolution** -- the driver step that rewrites a contextualized
  document's relative ids and relationship references to absolute DID URLs
  against the DID it was resolved under (DID Core's relative DID URL rule).
  Lives in `src/DidPeerDriver.ts`; the codec never does it. Avoid: absolutize,
  expand, canonicalize.
- **Fragment** -- the part of a verification method or service id after `#`.
  For library-generated keys it is the key's multibase Multikey value
  (`fingerprint()`), as in did-method-key and did-web-resolver. Avoid: key
  ref, ident (the Python helper's word), key index.
- **Long form store** -- the `get`/`set` object the driver consults to resolve
  short forms (`LongFormStore` in `src/types.ts`), filled by `generate()` and,
  when `rememberOnResolve` is on, by long-form resolution. Avoid: cache (that
  is `CachedResolver`'s word for its own LRU), registry.
- **Numalgo** -- the spec's name for the generation algorithm digit after
  `did:peer:`. This library implements numalgo 4 only. Avoid: version,
  method number.
- **Key suite** -- a registered key pair class (`use({ keyPairClass })`),
  identified by its 4-character multibase header. Same meaning as in
  did-method-key and did-web-resolver. Avoid: key type (reserved for the
  `keyType` option that selects a suite), algorithm.

## 13. Invariants (seed for ARCHITECTURE.md)

1. The hash is computed over the exact encoded-document string present in the
   DID, including its leading `z`; `decode` never re-serializes the document
   to verify it. Upheld in `src/numalgo4.ts` `decode`. Test: hash the
   substring after the second `:` and compare.
2. Resolution never enforces the input-document SHOULDs (`validateInputDocument`
   is called only on `generate()` paths); it applies the structural guard in
   section 6.2 so that hostile hash-valid input yields `invalidDid` and never
   a bare `TypeError`. Upheld by the contextualizer's guard and by
   `resolveLongForm`/`resolveShortForm` not calling `validateInputDocument`.
3. Contextualization deep-copies before mutating; the caller's document,
   including nested method objects and arrays, is not mutated, and the "absent
   `controller`" test is an own-property test. Upheld in the contextualizer.
4. The library-generated input document never contains a root `id`, an
   absolute `id` on a resource, a `controller` on a method exported from a
   live key pair (a third-party method arrives as a ready-made
   `IVerificationMethodEntry` and keeps the `controller` it came with), or two
   resources with one id. Upheld by `addVerificationMethod` and the
   `validateInputDocument` call on every `generate()` path. String references
   in relationships are not checked (section 6.3), so an absolute reference
   placed there by a caller-supplied `inputDocument` passes.
5. The only key suite imported at module load is `X25519KeyAgreementKey2020`,
   for `enableEncryptionKeyDerivation`; every other suite arrives through
   `use()`. Upheld by the import graph (`src/DidPeerDriver.ts`, mirroring
   did-method-key) and checked by a test over the compiled `dist/` import
   graph, which also asserts that `dist/codec.js` reaches no driver module
   and no key suite.
6. A short form resolves only through the configured `LongFormStore`, which
   the driver fills from `generate()` and from successful long-form `get()`s
   and reads for short forms; the driver keeps no memory of its own, and a
   stored long form is used only when its own short form equals the one
   requested. Upheld in `get()` steps 4 and 5 and in `generate()`.
7. The codec's resolved documents keep the input document's relative
   references unchanged; everything the driver returns (the DID document from
   `get({ did })` and `generate()`, the node from `get({ url })`, the live key
   pairs and their map keys) carries absolute DID URLs, produced by one
   reference-resolution step against the DID the document was resolved under.
   Upheld in the contextualizer (no rewriting) and in `DidPeerDriver`
   (rewriting in exactly one place).
8. Library-generated verification method fragments are the key's
   `fingerprint()` unless the caller overrides `fragment`. Precondition: the
   suite's `fingerprint()` equals its `publicKeyMultibase` (true for the
   Ed25519 and X25519 suites; a suite where it differs produces ids that do
   not repeat the key value, which is allowed but not the documented shape).
   Upheld in `addVerificationMethod`.
9. `method` is the string `'peer'`, the second colon-separated segment of a
   did:peer DID, which is what `CachedResolver.use()` keys on and `parseDid`
   returns. Upheld in `DidPeerDriver`.
10. The long-form and short-form regexes gate every string before decoding;
    the fixed `zQm` prefix and `{44}` length follow from base58 of a 2-byte
    sha2-256 multihash header plus 32 digest bytes being 46 characters
    starting `Qm`. Any future hash would need new regexes. The `{6,}` bound
    on the encoded document is the reference's; `{}` encodes to exactly 6
    characters, and no JSON object encodes shorter. Upheld in `numalgo4.ts`.

## 14. Alternatives rejected

- Porting the DIF TypeScript package or depending on `dbluhm/did-peer-4-ts`.
  Neither is published to npm in a consumable form, both pull `bs58` and
  `varint`, and the codec is under 200 lines. House rules prefer `@scure/base`
  and `@noble/hashes`.
- A private `PeerDID4Error` class (estoc port). `CachedResolver.resolveDID`
  only understands `DIDResolutionError`, so a private class would need a
  translation layer in the driver for no gain.
- Canonicalizing the input document (JCS) before hashing. The spec does not,
  the reference implementations do not, and doing so would make this library
  produce different DIDs from every other implementation for the same input.
  Do not reopen.
- Keeping relative references in the driver's output. Rejected 2026-11-05:
  the ecosystem's verifier needs absolute relationship entries (section 9
  item 5), and the size argument for relative output does not hold because
  the resolved document is never transmitted. Do not reopen without a verifier that
  resolves relative DID URLs against the controller id.
- Making the codec's output absolute as well. Rejected on 2026-11-05: it
  breaks the content-for-content comparison with the Python reference and
  gains nothing, because the driver does the rewriting for ecosystem
  consumers.
- Absolutizing only the `id` of verification method nodes while leaving the
  relationship strings relative. Does not work: the strict compare in
  `ControllerProofPurpose` runs against the relationship entries, and the
  document becomes internally inconsistent so did-io's by-id lookup stops
  finding the method. Do not reopen.
- Having consumers (documentLoaders, verifiers) make did:peer documents absolute.
  jsonld-signatures, did-io and every verifier would each need the change,
  and jsonld.js frames object input with an empty base, so there is no JSON-LD
  mechanism to lean on. Do not reopen.
- Indexed `#key-N` fragments for generated keys. Rejected on 2026-11-05
  (section 9 item 1) in favour of the ecosystem's fingerprint convention.
- Implementing numalgo 2 in the same release. Different wire grammar, its own
  abbreviation tables and service encoding; it deserves its own design doc.
  The layer map leaves it a slot.
- Shipping an in-memory `LongFormStore` class. A `Map` already satisfies the
  interface.

## 15. Open questions

Settled (2026-11-05):

1. `X25519KeyAgreementKey2020.fromEd25519()` exports type
   `X25519KeyAgreementKey2020` with the x25519-2020 context (section 7).
3. did-io's `findVerificationMethod` by `methodId` needs absolute ids, which
   driver output has after reference resolution (section 6.4,
   `publicMethodFor`).
5. References in driver output: absolute (section 9 item 5).
6. A `set` failure during a long-form `get()` rethrows as `internalError`
   (section 6.5, section 8).
7. Writes on resolution are controlled by the constructor option
   `rememberOnResolve`, default `true`; `generate()` always writes (section
   6.5).
8. `MAX_LONG_FORM_LENGTH` is an exported, non-configurable constant of 4096
   characters (section 6.2).
9. A `?query` or `/path` in a DID URL is stripped and the authority resolved,
   as in did-web-resolver (section 6.4 step 2).
10. Third-party-controlled methods are passed to `verificationMethods` as bare
    `IVerificationMethodEntry` values from data-integrity-core and placed
    verbatim with the default four purposes (sections 6.3 and 6.4).
11. The package has a `./codec` subpath export alongside `.` (section 6.1).

Still open:

2. Vectors 9 through 11 were derived by this design's own script and not
   cross-checked against the Python library in this environment (the review
   pass re-derived all twelve in JavaScript but could not run the Python
   package either). The implementation's first test run against the Python
   package settles them.
4. Whether the ecosystem wants `generate()` to default to producing a
   `keyAgreement` key for did:peer (DIDComm needs one), diverging from
   did-web-resolver's single-key default. This design keeps the sibling
   default and makes derivation opt-in through `use()`, matching
   did-method-key. Revisit after the first consumer (likely a DIDComm
   mediator client) lands.

Nothing else awaits a decision; every review-pass point is recorded in the
settled list above and in section 9.

## 16. Cross-repo follow-ups and process

The driving item is DMP-1. The decision records extracted from this design are
listed in the header.

Deliverables the design implies but did not list: rename the package from the
template name and fix its repository, homepage and bugs URLs; add the `./codec`
entry to the export map (section 6.1); add the section
5 dependencies at the siblings' ranges (`@noble/hashes` and `@scure/base`
`^2.2.0`, `@interop/bnid` `^6.0.2`, `@interop/did-io` `^4.2.2`,
`@interop/data-integrity-core` `^8.9.0`); delete the template `Example` module
and tests; seed ARCHITECTURE.md from sections 12 and 13; write the README
(usage from section 6.6, the non-ASCII interop note, the long-form-in-proofs
guidance, the store growth note); open the CHANGELOG at a new version with a
`TBD` date.

Proposed `touches:` list for the driving item (each entry is a reminder to
file follow-up work there, with the annotation it would carry today):

- did-io (README driver list, no ARCHITECTURE/AGENTS): add the did:peer
  driver to the supported list (it already lacks webvh). Candidate home for
  two in-house exports this design needs: the verification-method-type to
  context table (section 5) and the guarded `deepClone` helper that
  did-web-resolver keeps private (section 6.2). Filed 2026-11-05: switch
  `CachedResolver.resolveDID`'s `instanceof` to a `name`/`code` match
  (section 5): https://github.com/interop-alliance/did-io/issues/8. The
  relative-id hardening of `approvesMethodFor`/`_methodById` is no longer
  needed, since driver output is absolute.
- did-method-key (AGENTS.md): if the context table moves to did-io, consume it
  from there. Its AGENTS.md also describes the Multikey derivation branch as
  a no-op, which the code contradicts; a doc follow-up independent of this
  design.
- did-web-resolver: if `deepClone` and the context table move to did-io,
  consume them from there. Otherwise `unaffected`.
- jsonld-signatures, zcap, http-signature-zcap-verify: `unaffected` (driver
  output is absolute, so `ControllerProofPurpose` sees the same shape as for
  did:key and did:web). A did:peer verification test in each is still worth
  filing, since nothing exercises a did:peer controller today.
- did-cli-typescript (ARCHITECTURE.md): `src/edv/recipients.ts:185-195`
  passes relationship string entries straight to the documentLoader and
  filters `keyAgreement` methods by the `X25519KeyAgreementKey2020` type.
  With absolute driver output the first problem goes away for did:peer; the
  second still excludes a Multikey key agreement method. Its `did create`
  command lists key, web and webvh.
- security-document-loader: `unaffected` (its default resolver registers
  did:key and did:web and documents `.use()` for more; registering did:peer
  by default is a separate decision).
- verifier-core: `unaffected` (per-method opt-in resolvers, no did:peer
  special case).
- wallet-core, freewallet, dcw, pws-client, was-react, was-teaching-server,
  and the app-connect, encrypted-collections, portable-web-spaces and
  wallet-attached-storage specs: `unaffected` (no supported-method list that
  would change; freewallet's holder methods are key, web and webvh by design).
- did-method-webvh, bnid, x25519-key-agreement-key, ed25519-verification-key,
  data-integrity-core: `unaffected` (consumed as-is). x25519-key-agreement-key
  gains a follow-up only if a Multikey-typed derived key is ever wanted.
