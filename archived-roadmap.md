# Isomorphic Lib Template Roadmap -- archived (completed) items

Completed items from [ROADMAP.md](ROADMAP.md), moved here verbatim when they
ship so that item-number references (DMP-N) in the active roadmap, commit
messages, and design docs keep resolving. Append-only: newest at the bottom; do
not rewrite or summarize items on the way in. Ids remain permanent and are never
reused. CHANGELOG.md stays the record of _what_ landed; this file preserves each
item's acceptance criteria and context.

---

### DMP-1: did:peer numalgo 4 codec and did-io driver

- status: done (2026-11-05)
- priority: high
- labels: did-peer, codec, driver, did-io
- design: designs/DMP-1-did-peer-numalgo4.md
- design-approved: 2026-11-05
- touches:
  - did-io (README driver list; no ARCHITECTURE/AGENTS): shipped in did-io 4.3.0
    (2026-11-05): `contextsBySuite` and `deepClone` exports, consumed here from
    the registry; README driver list updated; the `instanceof` match in
    `CachedResolver.resolveDID` (issue #8) is replaced by
    `isDIDResolutionError()` in the did-io 4.3.0 working tree
  - did-method-key (AGENTS.md): follow-up: consume `contextsBySuite` (and
    `deepClone`) from did-io. Its AGENTS.md also describes the Multikey
    derivation branch as a no-op, which the code contradicts.
  - did-web-resolver: follow-up: consume `contextsBySuite` (and `deepClone`)
    from did-io
  - jsonld-signatures: unaffected: jsonld-signatures (driver output is absolute,
    so `ControllerProofPurpose` sees the same shape as for did:key and did:web)
  - zcap: unaffected: zcap (same reason as jsonld-signatures)
  - http-signature-zcap-verify: unaffected: http-signature-zcap-verify (same
    reason as jsonld-signatures)
  - did-cli-typescript (ARCHITECTURE.md): `src/edv/recipients.ts` filters
    `keyAgreement` methods by the `X25519KeyAgreementKey2020` type, which still
    excludes a Multikey key agreement method. The absolute-reference problem
    goes away for did:peer.
  - security-document-loader: unaffected: security-document-loader (its default
    resolver registers did:key and did:web; registering did:peer by default is a
    separate decision)
  - verifier-core: unaffected: verifier-core (per-method opt-in resolvers, no
    did:peer special case)
  - wallet-core, freewallet, dcw, pws-client, was-react, was-teaching-server,
    and the app-connect, encrypted-collections, portable-web-spaces and
    wallet-attached-storage specs: unaffected: wallet repos and specs (no
    supported-method list that would change)
  - did-method-webvh, bnid, x25519-key-agreement-key, ed25519-verification-key,
    data-integrity-core: unaffected: these packages (consumed as-is)
- acceptance:
  - [x] Codec passes all twelve test vectors (encode, decode, hash,
        contextualize)
  - [x] `validateInputDocument` enforces the validation rules, including id
        uniqueness
  - [x] `generate()` works on paths 1 to 3 (input document, seed, key pairs),
        including third-party verification method entries
  - [x] `LongFormStore` semantics hold, including `rememberOnResolve`
  - [x] `get()` handles DID URLs and resolves references to absolute DID URLs
  - [x] Error table behavior matches the design (codes and `cause`)
  - [x] did-io integration works (`CachedResolver.use`, `get`, `resolveDID`,
        `generate`)
  - [x] End-to-end signature and zcap verification passes with a did:peer
        controller
  - [x] Browser suite passes (the `structuredClone` fallback test was dropped
        2026-11-05; did-io's `deepClone` calls `structuredClone` directly)
  - [x] Dist import-graph test passes for the `./codec` export
  - [x] ARCHITECTURE.md seeded (glossary, invariants)
  - [x] README written
  - [x] Decision records 0001 to 0004 minted

Context: The ecosystem has drivers for did:key and did:web and none for
did:peer. Numalgo 4 is the form that DIDComm v2 agents exchange at first
contact. Its long form carries the whole DID document inside the identifier, and
its short form is a hash of that document. Without a driver, a wallet cannot
resolve a peer DID or verify a proof signed by a peer key. This item delivers a
pure codec, a `DidPeerDriver` for `@interop/did-io`, and a `LongFormStore` so
short forms resolve after the long form has been seen.

The design lives in
[designs/DMP-1-did-peer-numalgo4.md](designs/DMP-1-did-peer-numalgo4.md). In
brief, the codec stays spec-pure and keeps relative references. The driver
resolves those references to absolute DID URLs so that jsonld-signatures and
zcap verifiers accept the document. Library-generated fragments are the key
fingerprint. Errors are `DIDResolutionError`s thrown from the codec. Only
numalgo 4 is in scope. The design lists the wire-level decisions in section 9
and the cross-repo follow-ups in section 16.
