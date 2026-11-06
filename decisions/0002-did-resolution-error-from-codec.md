# 0002: The codec throws DIDResolutionError

- Status: accepted
- Date: 2026-11-05
- Driving work: the first release of the did:peer numalgo 4 driver.
- Affects: this repo's `src/numalgo4.ts` and `src/DidPeerDriver.ts`, and
  consumers that catch errors from the codec or from `CachedResolver`.

## Context

The codec and the driver both reject bad input: malformed DIDs, hash
mismatches, hostile document shapes. The estoc port of the codec uses a
private `PeerDID4Error` class.

`CachedResolver.resolveDID` in `@interop/did-io` recognizes failures as
`DIDResolutionError` and maps them to their `code`. Any other error becomes
`internalError` in the resolution envelope. A private error class would
therefore need a translation layer in the driver to produce the right envelope.

did-io 4.2.2 recognized the error with `instanceof`, which works only when this
package and did-io resolve to a single copy of `@interop/data-integrity-core`.
did-io 4.3.0 recognizes it with `isDIDResolutionError()` from
data-integrity-core 8.10.0, which also matches on `name` and `code`, so a
duplicated copy no longer breaks the envelope.

## Decision

The codec throws `DIDResolutionError` from `@interop/data-integrity-core`
directly, with `code: 'invalidDid'` for malformed or hostile input. The driver
adds no translation layer. Wrapped causes, such as a JSON parse failure, use
`new Error(message, { cause })`.

This package keeps the `@interop/data-integrity-core` range aligned with
did-io's, so both resolve to one copy where the package manager can arrange
it.

## Rejected Alternatives

- A private `PeerDID4Error` class. `CachedResolver.resolveDID` does not
  recognize it, so the driver would need a translation layer for no gain.
  This rejection is do-not-reopen.
- Switching on error `name` and `code` only inside this package. The
  recognition happens in did-io, so a local match would not change the
  envelope.

## Consequences

- `CachedResolver.resolveDID` produces the correct envelope code for every
  codec failure without help from the driver.
- With did-io 4.3.0 or later a duplicated copy of data-integrity-core in a
  consumer's dependency tree still yields the right envelope. With did-io
  4.2.2 it breaks the `instanceof` match silently: errors surface as
  `internalError`.
- `@interop/data-integrity-core` is a runtime dependency of the codec, so the
  codec is not dependency-free.
- Consumers should match on `name` and `code`, not `instanceof`.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A consumer needs a codec that does not depend on data-integrity-core. A
   private error class carrying `name: 'DIDResolutionError'` and a string
   `code` would now be recognized by did-io, but it would still need a reason
   to exist beyond that.

If revisited, keep the `code` values in the error table stable.
