import { createHash, randomBytes } from 'node:crypto';

const SRP_MODULUS = BigInt(
  `0xE67D2E994B2F900C3F41F08F5BB2627ED0D49EE1FE767A52EFCD565CD6E768812C3E1E9CE8F0A8BEA6CB13CD29DDEBF7A96D4A93B55D488DF099A15C89DCB0640738EB2CBDD9A8F7BAB561AB1B0DC1C6CDABF303264A08D1BCA932D1F1EE428B619D970F342ABA9A65793B8B2F041AE5364350C16F735F56ECBCA87BD57B29E7`,
);
const SRP_GENERATOR = 2n;
const SRP_MULTIPLIER = BigInt('1277432915985975349439481660349303019122249719989');
const SRP_FIELD_BYTES = 128;
const SRP_SALT_BYTES = 32;
const AUTH_LENGTH_BYTES = 2;
const MAX_AUTH_PAYLOAD_BYTES = AUTH_LENGTH_BYTES + SRP_SALT_BYTES * 2 + AUTH_LENGTH_BYTES + SRP_FIELD_BYTES * 2;
const PROOF_PREFIX = createProofPrefix();

interface ServerSrpChallenge {
  readonly salt: Buffer;
  readonly serverPublicKey: bigint;
}

function hashBytes(algorithm: string, ...parts: readonly Buffer[]): Buffer {
  const digest = createHash(algorithm.toLowerCase());

  for (const part of parts) {
    digest.update(part);
  }

  return digest.digest();
}

function sha1Bytes(...parts: readonly Buffer[]): Buffer {
  return hashBytes('sha1', ...parts);
}

function createProofPrefix(): Buffer {
  const modulusHash = unsignedBigIntToBuffer(bytesToBigInt(sha1Bytes(unsignedBigIntToBuffer(SRP_MODULUS))));
  const generatorHash = unsignedBigIntToBuffer(bytesToBigInt(sha1Bytes(unsignedBigIntToBuffer(SRP_GENERATOR))));
  return unsignedBigIntToBuffer(modPow(bytesToBigInt(modulusHash), bytesToBigInt(generatorHash), SRP_MODULUS));
}

function normalizeMod(value: bigint, modulus: bigint): bigint {
  return ((value % modulus) + modulus) % modulus;
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let factor = normalizeMod(base, modulus);
  let power = exponent;

  while (power > 0n) {
    if ((power & 1n) !== 0n) {
      result = (result * factor) % modulus;
    }

    power >>= 1n;
    factor = (factor * factor) % modulus;
  }

  return result;
}

function bytesToBigInt(value: Buffer): bigint {
  return value.length === 0 ? 0n : BigInt(`0x${value.toString('hex')}`);
}

function trimLeadingZeroBytes(value: Buffer): Buffer {
  let start = 0;

  while (start < value.length - 1 && value[start] === 0) {
    start++;
  }

  return value.subarray(start);
}

function unsignedBigIntToBuffer(value: bigint): Buffer {
  if (value === 0n) {
    return Buffer.from([0]);
  }

  let hex = value.toString(16);
  if (hex.length % 2 !== 0) {
    hex = `0${hex}`;
  }

  return trimLeadingZeroBytes(Buffer.from(hex, 'hex'));
}

function toHashField(value: bigint): Buffer {
  const bytes = unsignedBigIntToBuffer(value);
  return bytes.length > SRP_FIELD_BYTES ? bytes.subarray(bytes.length - SRP_FIELD_BYTES) : bytes;
}

function readSizedAsciiHex(buffer: Buffer, offset: number, maxLength: number, fieldName: string): [Buffer, number] {
  if (offset + AUTH_LENGTH_BYTES > buffer.length) {
    throw new Error(`Firebird server returned truncated SRP ${fieldName} length.`);
  }

  const length = buffer.readUInt16LE(offset);
  if (length > maxLength) {
    throw new Error(`Firebird server returned oversized SRP ${fieldName} (${length}).`);
  }

  const start = offset + AUTH_LENGTH_BYTES;
  const end = start + length;
  if (end > buffer.length) {
    throw new Error(`Firebird server returned truncated SRP ${fieldName}.`);
  }

  return [buffer.subarray(start, end), end];
}

function parseServerChallenge(authData: Buffer): ServerSrpChallenge {
  if (authData.length === 0) {
    throw new Error('Firebird server did not provide SRP authentication data.');
  }

  if (authData.length > MAX_AUTH_PAYLOAD_BYTES) {
    throw new Error(`Firebird server returned oversized SRP data (${authData.length}).`);
  }

  const [salt, keyLengthOffset] = readSizedAsciiHex(authData, 0, SRP_SALT_BYTES * 2, 'salt');
  const [serverPublicKeyHex, nextOffset] = readSizedAsciiHex(
    authData,
    keyLengthOffset,
    SRP_FIELD_BYTES * 2,
    'public key',
  );

  if (nextOffset !== authData.length) {
    throw new Error('Firebird server returned trailing SRP authentication data.');
  }

  return {
    salt: Buffer.from(salt),
    serverPublicKey: BigInt(`0x${serverPublicKeyHex.toString('ascii')}`),
  };
}

function deriveUserSecret(username: string, password: string, salt: Buffer): bigint {
  return bytesToBigInt(sha1Bytes(salt, sha1Bytes(Buffer.from(`${username}:${password}`, 'utf8'))));
}

function deriveScramble(clientPublicKey: bigint, serverPublicKey: bigint): bigint {
  return bytesToBigInt(sha1Bytes(toHashField(clientPublicKey), toHashField(serverPublicKey)));
}

function getEphemeralSecret(): bigint {
  return bytesToBigInt(randomBytes(32));
}

export class SrpClientSession {
  private readonly ephemeralSecret = getEphemeralSecret();
  private readonly publicValue = modPow(SRP_GENERATOR, this.ephemeralSecret, SRP_MODULUS);
  private sessionKey?: Buffer;

  constructor(private readonly proofHashAlgorithm: 'sha1' | 'sha256') {}

  getPublicKeyHex(): Buffer {
    return Buffer.from(toHashField(this.publicValue).toString('hex').toUpperCase(), 'ascii');
  }

  getSessionKey(): Buffer | undefined {
    return this.sessionKey;
  }

  createClientProof(username: string, password: string, authData: Buffer): Buffer {
    const { salt, serverPublicKey } = parseServerChallenge(authData);
    const verifierSecret = deriveUserSecret(username, password, salt);
    const scramble = deriveScramble(this.publicValue, serverPublicKey);
    const verifierPower = modPow(SRP_GENERATOR, verifierSecret, SRP_MODULUS);
    const sharedBase = normalizeMod(serverPublicKey - ((SRP_MULTIPLIER * verifierPower) % SRP_MODULUS), SRP_MODULUS);
    const sharedExponent = this.ephemeralSecret + scramble * verifierSecret;
    const sharedSecret = modPow(sharedBase, sharedExponent, SRP_MODULUS);
    const sessionKey = sha1Bytes(unsignedBigIntToBuffer(sharedSecret));
    const proof = hashBytes(
      this.proofHashAlgorithm,
      PROOF_PREFIX,
      trimLeadingZeroBytes(sha1Bytes(Buffer.from(username, 'utf8'))),
      salt,
      unsignedBigIntToBuffer(this.publicValue),
      unsignedBigIntToBuffer(serverPublicKey),
      sessionKey,
    );

    this.sessionKey = sessionKey;

    return Buffer.from(proof.toString('hex').toUpperCase(), 'ascii');
  }
}
