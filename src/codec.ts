/**
 * The `@interop/did-method-peer/codec` subpath: the pure numalgo 4 codec and
 * nothing from the driver, so a DIDComm library that only needs encode/decode
 * never loads `DidPeerDriver`, `@interop/bnid` or a key suite.
 */
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
  SHORT_FORM_PATTERN
} from './numalgo4.js'
export type { InputDocument } from './types.js'
