# 0004: Absolute references in driver output, relative in the codec

- Status: accepted
- Date: 2026-11-05
- Driving work: the first release of the did:peer numalgo 4 driver.
- Affects: this repo's `src/numalgo4.ts`, `src/DidPeerDriver.ts` and
  `src/codec.ts`. The behavior of jsonld-signatures, zcap and the did-io
  verifiers is a fixed party to this decision, which the driver accommodates.

## Context

A numalgo 4 input document uses relative ids and relative references, such as
`#z6Mk...` in `authentication`. The spec's contextualization step leaves them
relative and recommends against making them absolute.

The ecosystem's verifiers expect absolute entries. jsonld-signatures'
`ControllerProofPurpose` loads the controller document. It skips framing when
`@context[0]` is the DID v1 context. It then tests
`vm === verificationId || vm.id === verificationId` against the proof's
absolute method id. A relative `authentication: ["#z6Mk..."]` never equals
`did:peer:4...#z6Mk...`. Every Data Integrity proof and every zcap signed by a
did:peer key then fails `notAuthorized`, even though the key node resolves.
zcap's `CapabilityProofPurpose` extends the same class. Framing does not help,
because jsonld.js frames object input with an empty base.

did-io's `findVerificationMethod` also looks up a method by exact id match.
did:key and did:web documents are absolute, which is what these consumers are
calibrated for.

## Decision

The codec's `resolveLongForm` and `resolveShortForm` keep the spec's relative
form. They match the Python reference content for content.

The driver applies one reference resolution step to the codec's output. It
resolves relative ids against the DID the document was resolved under, per DID
Core's rule for relative DID URLs. The step rewrites:

- the `id` of every object entry in `verificationMethod`, the five
  relationships and `service`;
- every string entry in the five relationships.

Entries that start with `#` become `${authority}#${fragment}`. Entries that are
already absolute are left as they are. Nothing else changes. The result is the
document that `get({ did })` and `generate()` return. The live key pairs, the
`keyPairs` map keys and the node from `get({ url })` carry the same absolute
ids.

## Rejected Alternatives

All four rejections below are do-not-reopen.

- Relative references in driver output. This fails every Data Integrity proof
  and zcap signed by a did:peer key, as described above. The size argument for
  relative output does not hold, because the resolved document is built in
  memory and never transmitted. Only the long form is on the wire.
- Absolute references in the codec as well. This breaks the content-for-content
  comparison with the Python reference. It gains nothing, because the driver
  does the rewriting for ecosystem consumers. Codec users handle relative
  references as the spec requires.
- Making only the method `id` values absolute. The strict compare in
  `ControllerProofPurpose` runs against the relationship entries. The document
  also becomes internally inconsistent, and did-io's by-id lookup stops finding
  the method.
- Having consumers make did:peer documents absolute. jsonld-signatures, did-io
  and every verifier would each need the change. There is no JSON-LD mechanism
  to lean on.

## Consequences

- Driver output has the same shape as did:key and did:web documents.
  `ControllerProofPurpose`, `findVerificationMethod` and `approvesMethodFor`
  work without changes.
- The codec and the driver return different shapes for the same DID. Tests
  compare driver output against codec output after applying the same
  resolution.
- The two forms of one DID give different absolute ids. A node fetched by
  long-form URL carries the long form in `id` and `controller`. The same node
  fetched by short-form URL carries the short form. No verifier treats
  `alsoKnownAs` as an equivalence. A proof naming one form and a capability
  naming the other fails authorization. Wallets should put the long form in
  `proof.verificationMethod` and in zcap `controller` fields.
- `publicMethodFor` is documented for driver output. On a codec-returned
  document only purpose lookups work.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The ecosystem's verifiers resolve relative DID URLs against the controller
   id, so relative driver output passes `ControllerProofPurpose` and zcap
   verification.
2. A verifier treats `alsoKnownAs` entries as equivalent, which would remove
   the two-forms limitation.
3. A consumer needs the relative form from the driver, and the codec does not
   serve it.

If revisited, change the driver only. Keep the codec spec-pure.
