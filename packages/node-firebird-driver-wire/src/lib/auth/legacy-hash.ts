import { Buffer } from 'node:buffer';

import unixCryptTD from 'unix-crypt-td-js';

const FIREBIRD_LEGACY_SALT = '9z';
const LEGACY_PASSWORD_LIMIT = 8;

export function legacyHash(password: string, charset: BufferEncoding = 'utf8'): Buffer {
  const passwordBytes = Buffer.from(password, charset).subarray(0, LEGACY_PASSWORD_LIMIT);
  const cryptHash = unixCryptTD([...passwordBytes], FIREBIRD_LEGACY_SALT);

  return Buffer.from(cryptHash.slice(FIREBIRD_LEGACY_SALT.length), 'ascii');
}
