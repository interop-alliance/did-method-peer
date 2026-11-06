/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
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
  SHORT_FORM_PATTERN
} from './numalgo4.js'
export { validateInputDocument } from './inputDocument.js'
export type {
  DidPeerDriverOptions,
  FromMultibase,
  InputDocument,
  KeyPairClass,
  LongFormStore
} from './types.js'
