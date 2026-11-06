# @interop/did-method-peer Changelog

## 0.1.0 - 2026-11-06

### Added

- Initial release of the did:peer numalgo 4 driver for `@interop/did-io`
  (`DidPeerDriver`, `driver()`).
- Pure codec exports: `encodeLongForm`, `encodeShortForm`, `decode`,
  `longToShort`, `isDidPeer4`, `isLongForm`, `isShortForm`, `resolveLongForm`,
  `resolveShortForm`, `LONG_FORM_PATTERN`, `SHORT_FORM_PATTERN` and
  `MAX_LONG_FORM_LENGTH`. Also available from the
  `@interop/did-method-peer/codec` subpath, which loads no driver code.
- `validateInputDocument`.
- `LongFormStore` interface and the `rememberOnResolve` driver option.
- `generate()` from an input document, a seed, or key pairs, including
  third-party verification method entries.
- Reference resolution to absolute DID URLs in driver output.
- Test vectors from the Python reference and the spec tutorial.
- Decision-record convention: `decisions/` directory (README + TEMPLATE) for
  cross-repo decisions, plus the "Decision Records" section in AGENTS.md.
- Decision-record scope widened: a pre-implementation design review may also
  mint a record for a repo-internal do-not-reopen decision.
- Design-gate convention: `designs/` directory (README + TEMPLATE) for
  pre-implementation design docs on cross-cutting items, plus the `design:` /
  `design-approved:` item fields and gate rule in AGENTS.md.
- ARCHITECTURE.md skeleton (layer map, numbered invariants, ownership
  heuristics, current state labels), plus the "Architecture" section in
  AGENTS.md; the design gate, `touches:`, and the breaking-release audit all key
  on this file.
