import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

const TAG_KEY_TYPE = 0;
const TAG_KEY_PLUGINS = 1;
const TAG_PLUGIN_SPECIFIC = 3;

const PLUGIN_LIST_SEPARATOR = /[ \t,;]+/;

const CHACHA_BLOCK_WORDS = 16;
const CHACHA_BLOCK_BYTES = 64;
const CHACHA_CONSTANTS = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

export interface WireCryptPluginData {
  readonly keyType: string;
  readonly pluginName: string;
  readonly specificData?: Buffer;
}

interface StreamCipher {
  transform(data: Buffer): Buffer;
}

export interface WireCryptSession {
  readonly keyType: string;
  readonly pluginName: string;
  readonly incoming: StreamCipher;
  readonly outgoing: StreamCipher;
}

interface UntaggedClumplet {
  readonly tag: number;
  readonly value: Buffer;
}

interface KnownServerKey {
  readonly keyType: string;
  readonly plugins: readonly string[];
  readonly specificData: ReadonlyMap<string, Buffer>;
}

export class Rc4StreamCipher implements StreamCipher {
  private readonly state = new Uint8Array(256);
  private i = 0;
  private j = 0;

  constructor(key: Buffer) {
    if (key.length === 0) {
      throw new Error('RC4 key must not be empty.');
    }

    for (let index = 0; index < this.state.length; index++) {
      this.state[index] = index;
    }

    let j = 0;
    for (let index = 0; index < this.state.length; index++) {
      j = (j + this.state[index] + key[index % key.length]) & 0xff;
      this.swap(index, j);
    }
  }

  transform(data: Buffer): Buffer {
    const transformed = Buffer.allocUnsafe(data.length);

    for (let index = 0; index < data.length; index++) {
      this.i = (this.i + 1) & 0xff;
      this.j = (this.j + this.state[this.i]) & 0xff;
      this.swap(this.i, this.j);
      const keyByte = this.state[(this.state[this.i] + this.state[this.j]) & 0xff];
      transformed[index] = data[index] ^ keyByte;
    }

    return transformed;
  }

  private swap(left: number, right: number): void {
    const value = this.state[left];
    this.state[left] = this.state[right];
    this.state[right] = value;
  }
}

export class ChaChaStreamCipher implements StreamCipher {
  private readonly state = new Uint32Array(CHACHA_BLOCK_WORDS);
  private keystream: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  private keystreamOffset = 0;
  private overflowed = false;

  constructor(
    key: Buffer,
    nonce: Buffer,
    counter: bigint,
    private readonly counterBits: 32 | 64,
  ) {
    if (key.length !== 32) {
      throw new Error(`ChaCha key must contain exactly 32 bytes, got ${key.length}.`);
    }

    if (counterBits === 32 && nonce.length !== 12) {
      throw new Error(`ChaCha nonce must contain exactly 12 bytes, got ${nonce.length}.`);
    }

    if (counterBits === 64 && nonce.length !== 8) {
      throw new Error(`ChaCha64 nonce must contain exactly 8 bytes, got ${nonce.length}.`);
    }

    this.state.set(CHACHA_CONSTANTS, 0);

    for (let index = 0; index < 8; index++) {
      this.state[4 + index] = key.readUInt32LE(index * 4);
    }

    if (counterBits === 32) {
      this.state[12] = Number(counter & 0xffff_ffffn);
      this.state[13] = nonce.readUInt32LE(0);
      this.state[14] = nonce.readUInt32LE(4);
      this.state[15] = nonce.readUInt32LE(8);
    } else {
      this.state[12] = Number(counter & 0xffff_ffffn);
      this.state[13] = Number((counter >> 32n) & 0xffff_ffffn);
      this.state[14] = nonce.readUInt32LE(0);
      this.state[15] = nonce.readUInt32LE(4);
    }
  }

  transform(data: Buffer): Buffer {
    const transformed = Buffer.allocUnsafe(data.length);

    for (let index = 0; index < data.length; index++) {
      if (this.keystreamOffset >= this.keystream.length) {
        if (this.overflowed) {
          throw new Error('ChaCha stream counter overflowed. Reattach to the server to continue.');
        }

        this.keystream = this.generateBlock();
        this.keystreamOffset = 0;
        this.incrementCounter();
      }

      transformed[index] = data[index] ^ this.keystream[this.keystreamOffset++];
    }

    return transformed;
  }

  private generateBlock(): Uint8Array {
    const working = new Uint32Array(this.state);

    for (let round = 0; round < 10; round++) {
      this.quarterRound(working, 0, 4, 8, 12);
      this.quarterRound(working, 1, 5, 9, 13);
      this.quarterRound(working, 2, 6, 10, 14);
      this.quarterRound(working, 3, 7, 11, 15);
      this.quarterRound(working, 0, 5, 10, 15);
      this.quarterRound(working, 1, 6, 11, 12);
      this.quarterRound(working, 2, 7, 8, 13);
      this.quarterRound(working, 3, 4, 9, 14);
    }

    const block = Buffer.allocUnsafe(CHACHA_BLOCK_BYTES);
    for (let index = 0; index < CHACHA_BLOCK_WORDS; index++) {
      block.writeUInt32LE((working[index] + this.state[index]) >>> 0, index * 4);
    }

    return block;
  }

  private incrementCounter(): void {
    this.state[12] = (this.state[12] + 1) >>> 0;

    if (this.state[12] !== 0) {
      return;
    }

    if (this.counterBits === 32) {
      this.overflowed = true;
      return;
    }

    this.state[13] = (this.state[13] + 1) >>> 0;
    if (this.state[13] === 0) {
      this.overflowed = true;
    }
  }

  private quarterRound(state: Uint32Array, a: number, b: number, c: number, d: number): void {
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotateLeft(state[d] ^ state[a], 16);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotateLeft(state[b] ^ state[c], 12);
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotateLeft(state[d] ^ state[a], 8);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotateLeft(state[b] ^ state[c], 7);
  }
}

export function parseWireCryptPluginData(buffers: readonly Buffer[]): WireCryptPluginData[] {
  return buffers.flatMap((buffer) =>
    parseKnownServerKeys(buffer).flatMap(({ keyType, plugins, specificData }) =>
      plugins.map((pluginName) => ({
        keyType,
        pluginName,
        specificData: specificData.get(pluginName),
      })),
    ),
  );
}

export function createWireCryptSession(buffers: readonly Buffer[], sessionKey: Buffer): WireCryptSession | undefined {
  for (const pluginData of parseWireCryptPluginData(buffers)) {
    if (pluginData.keyType !== 'Symmetric') {
      continue;
    }

    if (pluginData.pluginName === 'Arc4') {
      return {
        keyType: pluginData.keyType,
        pluginName: pluginData.pluginName,
        incoming: new Rc4StreamCipher(Buffer.from(sessionKey)),
        outgoing: new Rc4StreamCipher(Buffer.from(sessionKey)),
      };
    }

    if (pluginData.pluginName === 'ChaCha') {
      return createChaChaSession(pluginData, sessionKey);
    }

    if (pluginData.pluginName === 'ChaCha64') {
      return createChaCha64Session(pluginData, sessionKey);
    }
  }

  return undefined;
}

function createChaChaSession(pluginData: WireCryptPluginData, sessionKey: Buffer): WireCryptSession {
  const iv = pluginData.specificData;
  if (!iv || (iv.length !== 12 && iv.length !== 16)) {
    throw new Error(`Firebird returned an invalid ChaCha IV (${iv?.length ?? 0} bytes).`);
  }

  const key = stretchChaChaKey(sessionKey);
  const nonce = iv.subarray(0, 12);
  const counter = iv.length === 16 ? BigInt(iv.readUInt32BE(12)) : 0n;

  return {
    keyType: pluginData.keyType,
    pluginName: pluginData.pluginName,
    incoming: new ChaChaStreamCipher(key, nonce, counter, 32),
    outgoing: new ChaChaStreamCipher(key, nonce, counter, 32),
  };
}

function createChaCha64Session(pluginData: WireCryptPluginData, sessionKey: Buffer): WireCryptSession {
  const iv = pluginData.specificData;
  if (!iv || iv.length !== 8) {
    throw new Error(`Firebird returned an invalid ChaCha64 IV (${iv?.length ?? 0} bytes).`);
  }

  const key = stretchChaChaKey(sessionKey);

  return {
    keyType: pluginData.keyType,
    pluginName: pluginData.pluginName,
    incoming: new ChaChaStreamCipher(key, iv, 0n, 64),
    outgoing: new ChaChaStreamCipher(key, iv, 0n, 64),
  };
}

function stretchChaChaKey(sessionKey: Buffer): Buffer {
  if (sessionKey.length < 16) {
    throw new Error(`Firebird returned a ChaCha session key that is too short (${sessionKey.length} bytes).`);
  }

  return Buffer.from(createHash('sha256').update(sessionKey).digest());
}

function parseKnownServerKeys(buffer: Buffer): KnownServerKey[] {
  const clumplets = readTraditionalClumplets(buffer);
  const keys: KnownServerKey[] = [];
  let currentKeyType: string | undefined;
  let currentPlugins: string[] = [];
  let currentSpecificData = new Map<string, Buffer>();

  const flushCurrent = (): void => {
    if (!currentKeyType || currentPlugins.length === 0) {
      return;
    }

    keys.push({
      keyType: currentKeyType,
      plugins: [...currentPlugins],
      specificData: new Map(currentSpecificData),
    });
  };

  for (const { tag, value } of clumplets) {
    if (tag === TAG_KEY_TYPE) {
      flushCurrent();
      currentKeyType = value.toString('latin1');
      currentPlugins = [];
      currentSpecificData = new Map();
      continue;
    }

    if (tag === TAG_KEY_PLUGINS) {
      currentPlugins = value
        .toString('latin1')
        .split(PLUGIN_LIST_SEPARATOR)
        .filter((entry) => entry.length > 0);
      continue;
    }

    if (tag === TAG_PLUGIN_SPECIFIC) {
      const separator = value.indexOf(0);
      if (separator <= 0) {
        continue;
      }

      currentSpecificData.set(value.subarray(0, separator).toString('latin1'), Buffer.from(value.subarray(separator + 1)));
    }
  }

  flushCurrent();

  return keys;
}

function readTraditionalClumplets(buffer: Buffer): UntaggedClumplet[] {
  const clumplets: UntaggedClumplet[] = [];
  let offset = 0;

  while (offset < buffer.length) {
    if (offset + 2 > buffer.length) {
      throw new Error('Invalid wire crypt data: missing clumplet header.');
    }

    const tag = buffer[offset++];
    const length = buffer[offset++];

    if (offset + length > buffer.length) {
      throw new Error(`Invalid wire crypt data: clumplet ${tag} overruns the buffer.`);
    }

    clumplets.push({
      tag,
      value: buffer.subarray(offset, offset + length),
    });
    offset += length;
  }

  return clumplets;
}

function rotateLeft(value: number, count: number): number {
  return ((value << count) | (value >>> (32 - count))) >>> 0;
}
