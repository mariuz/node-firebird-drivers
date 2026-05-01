import { Buffer } from 'node:buffer';

export class XdrWriter {
  private readonly chunks: Buffer[] = [];

  writeInt32(value: number): void {
    const buffer = Buffer.alloc(4);
    buffer.writeInt32BE(value, 0);
    this.chunks.push(buffer);
  }

  writeInt64(value: bigint): void {
    const buffer = Buffer.alloc(8);
    buffer.writeBigInt64BE(value, 0);
    this.chunks.push(buffer);
  }

  writeBytes(value: Buffer): void {
    this.chunks.push(value);
  }

  writeBuffer(value: Buffer): void {
    this.writeInt32(value.length);
    if (value.length > 0) {
      this.writeBytes(value);
      this.writeAlignment(value.length);
    }
  }

  writeString(value: string): void {
    this.writeBuffer(Buffer.from(value, 'utf8'));
  }

  writeAlignment(length: number): void {
    const paddingLength = (4 - (length % 4)) & 3;
    if (paddingLength > 0) {
      this.writeBytes(Buffer.alloc(paddingLength));
    }
  }

  toBuffer(): Buffer {
    return Buffer.concat(this.chunks);
  }
}

export class XdrParser {
  private offset = 0;

  constructor(private readonly buffer: Buffer) {}

  readInt32(): number {
    const value = this.buffer.readInt32BE(this.offset);
    this.offset += 4;
    return value;
  }

  readInt64(): bigint {
    const value = this.buffer.readBigInt64BE(this.offset);
    this.offset += 8;
    return value;
  }

  readBuffer(): Buffer {
    const length = this.readInt32();
    const value = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    this.offset += (4 - (length % 4)) & 3;
    return value;
  }

  readString(): string {
    return this.readBuffer().toString('utf8');
  }
}

export function writeTraditionalClumplet(tag: number, value: Buffer): Buffer {
  if (value.length > 255) {
    throw new Error(`Clumplet ${tag} is too large for a traditional buffer.`);
  }

  return Buffer.concat([Buffer.from([tag, value.length]), value]);
}

export function writeWideClumplet(tag: number, value: Buffer): Buffer {
  const header = Buffer.alloc(5);
  header.writeUInt8(tag, 0);
  header.writeUInt32LE(value.length, 1);
  return Buffer.concat([header, value]);
}

export function writeWideStringClumplet(tag: number, value: string): Buffer {
  return writeWideClumplet(tag, Buffer.from(value, 'utf8'));
}
