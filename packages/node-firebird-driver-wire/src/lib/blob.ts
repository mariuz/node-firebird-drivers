import { AttachmentImpl } from './attachment';

import { Blob, BlobSeekWhence, CreateBlobOptions } from 'node-firebird-driver';
import { AbstractBlobStream, blobInfo, createBpb, getPortableInteger } from 'node-firebird-driver/dist/lib/impl';

import { BlobHandle } from './internal/wire-protocol';
import { TransactionImpl } from './transaction';

const MAX_SEGMENT_SIZE = 65535;
const BLOB_LENGTH_INFO_ITEMS = Buffer.from([blobInfo.totalLength]);

function decodePackedBlobSegments(buffer: Buffer): Buffer[] {
  const segments: Buffer[] = [];
  let offset = 0;

  while (offset + 2 <= buffer.length) {
    const length = buffer.readUInt16LE(offset);
    offset += 2;
    if (offset + length > buffer.length) {
      throw new Error('Invalid packed blob segment buffer.');
    }
    segments.push(Buffer.from(buffer.subarray(offset, offset + length)));
    offset += length;
  }

  if (offset !== buffer.length) {
    throw new Error('Packed blob segment buffer has trailing bytes.');
  }

  return segments;
}

export class BlobStreamImpl extends AbstractBlobStream {
  override attachment: AttachmentImpl;
  blobHandle?: BlobHandle;
  private position = 0;
  private readBuffer = Buffer.alloc(0);
  private eofPending = false;
  private eofReached = false;

  static async create(
    attachment: AttachmentImpl,
    transaction: TransactionImpl,
    options?: CreateBlobOptions,
  ): Promise<BlobStreamImpl> {
    const blobHandle = await attachment.protocol!.createBlob(transaction.transactionHandle!, createBpb(options));
    const blob = new Blob(attachment, blobHandle.id);
    const blobStream = new BlobStreamImpl(blob, attachment);
    blobStream.blobHandle = blobHandle;
    return blobStream;
  }

  static async open(attachment: AttachmentImpl, transaction: TransactionImpl, blob: Blob): Promise<BlobStreamImpl> {
    const blobStream = new BlobStreamImpl(blob, attachment);
    blobStream.blobHandle = await attachment.protocol!.openBlob(transaction.transactionHandle!, blob.id);
    return blobStream;
  }

  protected async internalGetLength(): Promise<number> {
    const infoRet = await this.attachment.protocol!.getBlobInfo(this.blobHandle!, BLOB_LENGTH_INFO_ITEMS);

    if (infoRet[0] != blobInfo.totalLength) {
      throw new Error('Unrecognized response from blob info.');
    }

    const size = getPortableInteger(infoRet.subarray(1), 2);
    return getPortableInteger(infoRet.subarray(3), size);
  }

  protected async internalClose(): Promise<void> {
    await this.attachment.protocol!.closeBlob(this.blobHandle!);
    this.blobHandle = undefined;
  }

  protected async internalCancel(): Promise<void> {
    await this.attachment.protocol!.cancelBlob(this.blobHandle!);
    this.blobHandle = undefined;
  }

  protected async internalSeek(offset: number, whence?: BlobSeekWhence): Promise<number> {
    this.readBuffer = Buffer.alloc(0);
    this.eofPending = false;
    this.eofReached = false;

    const mode = whence ?? BlobSeekWhence.START;
    const seekMode = mode === BlobSeekWhence.CURRENT ? BlobSeekWhence.START : mode;
    const seekOffset = mode === BlobSeekWhence.CURRENT ? this.position + offset : offset;
    const position = await this.attachment.protocol!.seekBlob(this.blobHandle!, seekMode, seekOffset);
    this.position = position;
    return position;
  }

  protected async internalRead(buffer: Buffer): Promise<number> {
    while (this.readBuffer.length < buffer.length && !this.eofPending && !this.eofReached) {
      const response = await this.attachment.protocol!.getSegment(this.blobHandle!, MAX_SEGMENT_SIZE);
      const segmentData = Buffer.concat(decodePackedBlobSegments(response.data));

      if (segmentData.length > 0) {
        this.readBuffer = this.readBuffer.length === 0 ? segmentData : Buffer.concat([this.readBuffer, segmentData]);
      }

      if (response.state === 2) {
        this.eofPending = true;
      }

      if (segmentData.length === 0) {
        this.eofReached = true;
        this.eofPending = false;
        break;
      }
    }

    if (this.readBuffer.length === 0) {
      if (this.eofPending) {
        this.eofReached = true;
        this.eofPending = false;
      }

      if (this.eofReached) {
        return -1;
      }
    }

    const readBytes = Math.min(buffer.length, this.readBuffer.length);
    this.readBuffer.copy(buffer, 0, 0, readBytes);
    this.readBuffer = this.readBuffer.subarray(readBytes);
    this.position += readBytes;

    if (this.readBuffer.length === 0 && this.eofPending) {
      this.eofReached = true;
      this.eofPending = false;
    }

    return readBytes;
  }

  protected async internalWrite(buffer: Buffer): Promise<void> {
    while (buffer.length > 0) {
      const writingBytes = Math.min(buffer.length, MAX_SEGMENT_SIZE);
      await this.attachment.protocol!.putSegment(this.blobHandle!, buffer.subarray(0, writingBytes));
      this.position += writingBytes;
      buffer = buffer.subarray(writingBytes);
    }
  }

  get isValid(): boolean {
    return !!this.blobHandle && this.attachment.isValid;
  }
}
