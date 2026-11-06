# did:peer numalgo 4 driver _(@interop/did-method-peer)_

[![Node.js CI](https://github.com/interop-alliance/did-method-peer/workflows/CI/badge.svg)](https://github.com/interop-alliance/did-method-peer/actions?query=workflow%3A%22CI%22)
[![NPM Version](https://img.shields.io/npm/v/@interop/did-method-peer.svg)](https://npm.im/@interop/did-method-peer)

> A `did:peer` numalgo 4 codec and driver for `@interop/did-io`, for use in the
> browser, Node.js, and React Native.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)

## Background

The [peer DID method](https://identity.foundation/peer-did-method-spec/) defines
several algorithms, called numalgos. Numalgo 4 is the current one. It is
statically resolvable. The DID carries everything needed to resolve it, and no
registry or network is involved.

A numalgo 4 DID starts from an input document. The input document looks like the
eventual DID document with four differences:

- it has no root `id`;
- every identifier defined in it is relative (`#key-0`);
- every reference to a resource in it is relative;
- a verification method omits `controller` when the controller is the document
  owner.

To encode it, the input document is serialized as JSON without whitespace,
prefixed with the multicodec `json` code, and encoded as base58btc multibase.
That string is the encoded document. The SHA2-256 hash of the encoded document
string, as a multihash in base58btc, is the hash. Then:

- The long form is `did:peer:4{hash}:{encoded document}`. It carries the whole
  document and resolves with no other input.
- The short form is `did:peer:4{hash}`. It is shorter, but it can only be
  resolved by a party that has already seen the long form.

DIDComm v2 agents send the long form at first contact and the short form in
every message after that.

This package provides:

- A pure codec: `encodeLongForm`, `encodeShortForm`, `decode`, `longToShort`,
  `resolveLongForm` and `resolveShortForm`, plus the form checks and regexes.
- A `@interop/did-io` driver with `generate()`, `get()`, `fromKeyPair()`,
  `publicKeyToDidDoc()` and `publicMethodFor()`.
- Input document validation.
- A `LongFormStore` contract for resolving short forms.

Out of scope:

- Numalgos 0, 1, 2 and 3. `get()` rejects those DIDs with `DIDResolutionError`
  `methodNotSupported`.
- A DID Resolution `resolveDID()` method on the driver. `CachedResolver` adapts
  `get()` into a resolution result.
- A persistent long form store. The driver defines the contract and ships no
  store of its own.

## Security

- The hash protects against corruption. It does not protect against a hostile
  sender, because the sender computes the hash over a document of their choice.
  A valid hash proves the document is the one the DID names. It does not prove
  the document is trustworthy.
- `decode` rejects any long form longer than `MAX_LONG_FORM_LENGTH` (4096
  characters) before hashing or decoding it. This stops a multi-megabyte DID
  string from blocking the event loop. The limit is not configurable.
- Resolution does not validate the input document beyond a structural guard. A
  hash-valid document with an unusable shape fails with `DIDResolutionError`
  `invalidDid`.
- `alsoKnownAs` entries other than the one the library appends, and any
  `controller` value naming a different DID, are claims made by the
  counterparty. The library passes them through and does not verify them.
- A document's `@context` is supplied by the counterparty. Remote context
  fetching is the consumer's documentLoader policy.

## Install

- Node.js 24+ is recommended.

### PNPM

To install via PNPM:

```
pnpm install @interop/did-method-peer
```

### Development

To install locally (for development):

```
git clone https://github.com/interop-alliance/did-method-peer.git
cd did-method-peer
pnpm install
```

## Usage

### With did-io

```js
import { CachedResolver } from '@interop/did-io'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import * as didPeer from '@interop/did-method-peer'

const didPeerDriver = didPeer.driver({ longFormStore: new Map() })
didPeerDriver.use({
  keyPairClass: Ed25519VerificationKey,
  enableEncryptionKeyDerivation: true
})

const resolver = new CachedResolver()
resolver.use(didPeerDriver)

const { didDocument, keyPairs, methodFor } = await didPeerDriver.generate()

// Long form, resolved offline
await resolver.get({ did: didDocument.id })

// Key node, id is `${longForm}#z6Mk...`
const signingKey = methodFor({ purpose: 'authentication' })
await resolver.get({ url: signingKey.id })

// Short form, resolved through the long form store
await resolver.get({ did: didDocument.alsoKnownAs[0] })
```

`resolver.generate({ method: 'peer' })` also works, because the driver exposes
`generate`.

### Codec only

An application that only needs to encode and decode DIDs imports the `./codec`
subpath. It does not load the driver or any key suite.

```js
import {
  encodeLongForm,
  decode,
  resolveLongForm,
  longToShort
} from '@interop/did-method-peer/codec'

const inputDocument = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  verificationMethod: [
    {
      id: '#key-0',
      type: 'Multikey',
      publicKeyMultibase: 'z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V'
    }
  ],
  authentication: ['#key-0']
}

const longForm = encodeLongForm({ inputDocument })
const shortForm = longToShort({ did: longForm })

// The input document as it was encoded, relative ids intact
const decoded = decode({ did: longForm })

// The contextualized DID document, relative references left relative
const didDocument = resolveLongForm({ did: longForm })
```

`encodeLongForm` and `encodeShortForm` do not validate. The codec functions are
synchronous. They throw `DIDResolutionError` with `code: 'invalidDid'` for
malformed input.

### Creating a DID with `generate()`

`generate()` takes one of three mutually exclusive entry paths. It returns
`{ didDocument, keyPairs, methodFor }`. `didDocument.id` is the long form.

- `inputDocument`. The library validates, encodes and resolves a document you
  built. An optional `keyPairs` map, keyed by bare fragment, binds live key
  pairs to methods in that document. A pair whose public key differs from the
  document's method is a `TypeError`. A method serialized without
  `publicKeyMultibase` (a 2018 suite's `publicKeyBase58`, a JSON Web Key) is
  read through the pair's registered suite for the comparison.
- `seed`. A `Uint8Array` of exactly 32 bytes, or a string in `z1A...` form. The
  library generates one key pair from it and proceeds as in the third path. The
  same seed always yields the same DID.
- Nothing, or explicit key pairs. With no options, the library generates one
  random key pair with the registered suite. Otherwise you pass
  `verificationKeyPair`, `keyAgreementKeyPair`, `verificationMethods` and
  `service`.

Details of the third path:

- The verification key gets the purposes `authentication`, `assertionMethod`,
  `capabilityDelegation` and `capabilityInvocation`.
- The default fragment is the key's `fingerprint()`, so a method id looks like
  `#z6Mk...`. A `verificationMethods` entry of the form
  `{ keyPair, fragment, purposes }` overrides the fragment and the purposes.
- A `verificationMethods` entry can also be a third-party method. Pass a string
  DID URL, or a full verification method object whose `controller` names the
  other DID. It is placed as given and gets the four default purposes. To give
  it other purposes, wrap it as `{ method, purposes }`.
- With `enableEncryptionKeyDerivation`, an Ed25519 key also yields a derived
  `X25519KeyAgreementKey2020` key under `keyAgreement`. Derivation is opt-in,
  because it uses one key's material for both signing and encryption.
- `service` is copied as given.

Mixing paths is a `TypeError`. For example, `inputDocument` together with
`seed`, or `seed` together with `verificationKeyPair`.

`methodFor({ purpose })` returns the live key pair for that purpose. It throws
when no method serves the purpose, and when the method has no live pair.

### The long form store

A short form is only a hash. To resolve one, the driver must have seen the long
form it belongs to. The spec says a short form cannot be resolved without first
seeing and storing its long form.

`LongFormStore` is that memory. It maps a short form to its long form:

```ts
interface LongFormStore {
  get(shortForm: string): string | undefined | Promise<string | undefined>
  set(shortForm: string, longForm: string): unknown
}
```

A plain `Map<string, string>` satisfies it. A persistent store (IndexedDB, a
wallet's encrypted storage) implements the same two methods and returns
promises. The driver awaits both methods. There is no default store. Without
one, every short form fails with `DIDResolutionError` `notFound`.

The driver uses the store like this:

- `generate()` always writes the new DID's pair, so the creator can resolve its
  own short form.
- `get({ did })` with a long form writes the pair after a successful resolution,
  when `rememberOnResolve` is on.
- `get({ did })` with a short form reads the store. It never writes.
- `publicKeyToDidDoc()` does not write.

`rememberOnResolve` is a constructor option and defaults to `true`. DIDComm
clients keep the default, since the counterparty sends its long form once. A
verifier that only fetches key nodes for signature checks should set it to
`false`. Otherwise every key fetch is a durable write, and a store failure would
fail the verification.

```js
const verifierDriver = didPeer.driver({
  longFormStore: store,
  rememberOnResolve: false
})
```

An application that wants to gate contact acceptance resolves with
`rememberOnResolve: false`. It writes `store.set(longToShort({ did }), did)`
itself when it accepts the contact.

A stored long form is checked on the way out. `decode` checks it against its own
hash. The driver then checks that the long form's short form equals the one
requested. A corrupt or mis-keyed entry fails with `invalidDid`. A store that
throws or rejects fails with `internalError`, with the store error as `cause`. A
failed store write in a long form `get()` also fails with `internalError`.

Store growth. A store that writes on sight gains one entry per distinct long
form resolved. Any counterparty can mint unlimited distinct long forms. A
persistent store is therefore unbounded by construction. The store implementer
owns bounds and eviction.

The long form store is separate from the `CachedResolver` cache. That cache
memoizes successful results by exact DID string for a few seconds. It knows
nothing about short and long forms.

### Errors

| condition                                                                                     | thrown                                                       |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| bad argument shape (`did` missing, both `inputDocument` and `seed`, ...)                      | `TypeError`                                                  |
| not `did:peer:`                                                                               | `DIDResolutionError` `methodNotSupported`                    |
| `did:peer:` with numalgo other than 4                                                         | `DIDResolutionError` `methodNotSupported`                    |
| fails the long form regex, hash mismatch, bad multibase or multicodec prefix, non-object JSON | `DIDResolutionError` `invalidDid`                            |
| short form with no stored long form                                                           | `DIDResolutionError` `notFound`                              |
| stored long form's short form differs from the one requested                                  | `DIDResolutionError` `invalidDid`                            |
| store `get` throws or rejects                                                                 | `DIDResolutionError` `internalError`, store error as `cause` |
| store `set` rejects in `generate()`                                                           | `generate()` rejects with the store error as `cause`         |
| store `set` rejects in `get()` (long form)                                                    | `DIDResolutionError` `internalError`, store error as `cause` |
| hash-valid document whose shape contextualization cannot handle                               | `DIDResolutionError` `invalidDid`                            |
| long form over `MAX_LONG_FORM_LENGTH`                                                         | `DIDResolutionError` `invalidDid`                            |
| more than one `#` in a DID URL                                                                | `DIDResolutionError` `invalidDidUrl`                         |
| `?query` or `/path` in a DID URL                                                              | stripped, and the authority resolves (no error)              |
| fragment not in document                                                                      | `VerificationMethodError` `notFound`                         |
| input document fails `validateInputDocument`                                                  | `TypeError` with the failing path in the message             |
| unsupported multibase header, no or multiple suites                                           | plain `Error`                                                |

No `TypeError` leaves resolution. A counterparty's document can only produce
`DIDResolutionError`s. Match on `name` and `code`.

`DIDResolutionError` comes from `@interop/data-integrity-core`. `CachedResolver`
(did-io 4.3.0 and later) recognizes it by `name` and `code`, so a duplicated
copy of that package in your dependency tree does not change the envelope.

### Notes for implementers

- Absolute and relative references. The driver returns absolute DID URLs. The
  document from `get({ did })` and `generate()`, and the node from
  `get({ url })`, use ids like `${did}#z6Mk...`. This is what the ecosystem's
  verifiers compare against. The codec functions `resolveLongForm` and
  `resolveShortForm` keep relative references, as the spec does.
- Use the long form in proofs. A node fetched by long form URL carries the long
  form in `id` and `controller`. The same node fetched by short form URL carries
  the short form. No verifier in the ecosystem treats `alsoKnownAs` as an
  equivalence. A proof naming one form and a capability controller naming the
  other fails authorization. Put the long form in `proof.verificationMethod` and
  in zcap `controller` fields. It resolves with no store, and it survives a lost
  store.
- `MAX_LONG_FORM_LENGTH` is 4096 characters, the longest base58 string the
  `@scure/base` codec decodes. It is exported so callers can see it. The encoder
  has its own limit of 2048 bytes of input; a larger input document fails
  `encodeLongForm` and `generate()` with an `Error` naming the size.
- Non-ASCII interop. The library serializes the input document with
  `JSON.stringify`, which emits non-ASCII characters raw. Python's `json.dumps`
  escapes them by default. An identical input document containing non-ASCII text
  therefore yields a different long form from the Python library. Resolution is
  unaffected, because the hash covers the bytes the creator produced. Only
  independent re-derivation of the same DID from the same document differs.
  `JSON.stringify` also emits integer-like keys first and serializes floats
  differently from Python. Published test vectors are all ASCII.
- DID URL queries. A `?query` or `/path` is stripped and ignored. A `?service=`
  URL resolves to the document, or to the node named by its fragment.
- The library does not canonicalize the input document. Key order and formatting
  are preserved as given.

## Contribute

PRs accepted. See [CONTRIBUTING.md](CONTRIBUTING.md) for editor setup (Prettier,
ESLint, and EditorConfig) and how it maps to CI.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT License](LICENSE.md) © 2026 Interop Alliance.
