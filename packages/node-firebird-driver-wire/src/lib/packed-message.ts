import { endianness } from 'node:os';

import { sqlTypes } from 'node-firebird-driver/dist/lib/impl';

import { StatementColumn } from './protocol-types';
import { SocketChannel } from './socket-channel';
import { XdrWriter } from './xdr';

const LITTLE_ENDIAN = endianness() === 'LE';

export async function readPackedMessageBuffer(
  channel: SocketChannel,
  columns: readonly StatementColumn[],
  messageLength: number,
): Promise<Buffer> {
  const rowBuffer = Buffer.alloc(messageLength);
  const view = new DataView(rowBuffer.buffer, rowBuffer.byteOffset, rowBuffer.byteLength);
  const flagBytes = Math.ceil(columns.length / 8);
  const nullBitmap = await readPaddedOpaque(channel, flagBytes);

  for (let index = 0; index < columns.length; index++) {
    const column = columns[index];
    const isNull = (nullBitmap[index >> 3] & (1 << (index & 7))) !== 0;
    view.setInt16(column.nullOffset, isNull ? -1 : 0, LITTLE_ENDIAN);
    if (isNull) {
      continue;
    }

    switch (column.type) {
      case sqlTypes.SQL_TEXT: {
        const value = await readPaddedOpaque(channel, column.length);
        value.copy(rowBuffer, column.offset);
        break;
      }

      case sqlTypes.SQL_VARYING: {
        const valueLength = await readXdrInt32(channel);
        const value = await readPaddedOpaque(channel, valueLength);
        view.setUint16(column.offset, valueLength, LITTLE_ENDIAN);
        value.copy(rowBuffer, column.offset + 2);
        break;
      }

      case sqlTypes.SQL_TYPE_DATE:
      case sqlTypes.SQL_TYPE_TIME:
        view.setInt32(column.offset, await readXdrInt32(channel), LITTLE_ENDIAN);
        break;

      case sqlTypes.SQL_TIME_TZ_EX:
        view.setInt32(column.offset, await readXdrInt32(channel), LITTLE_ENDIAN);
        view.setUint16(column.offset + 4, decodeTimeZoneValue(await readXdrInt32(channel)), LITTLE_ENDIAN);
        view.setInt16(column.offset + 6, decodeTimeZoneOffset(await readXdrInt32(channel)), LITTLE_ENDIAN);
        break;

      case sqlTypes.SQL_DOUBLE: {
        const value = await channel.readExactly(8);
        view.setFloat64(column.offset, value.readDoubleBE(0), LITTLE_ENDIAN);
        break;
      }

      case sqlTypes.SQL_TIMESTAMP:
        view.setInt32(column.offset, await readXdrInt32(channel), LITTLE_ENDIAN);
        view.setInt32(column.offset + 4, await readXdrInt32(channel), LITTLE_ENDIAN);
        break;

      case sqlTypes.SQL_TIMESTAMP_TZ_EX:
        view.setInt32(column.offset, await readXdrInt32(channel), LITTLE_ENDIAN);
        view.setInt32(column.offset + 4, await readXdrInt32(channel), LITTLE_ENDIAN);
        view.setUint16(column.offset + 8, decodeTimeZoneValue(await readXdrInt32(channel)), LITTLE_ENDIAN);
        view.setInt16(column.offset + 10, await readXdrInt32(channel), LITTLE_ENDIAN);
        break;

      case sqlTypes.SQL_BOOLEAN: {
        const value = await readPaddedOpaque(channel, 1);
        rowBuffer[column.offset] = value[0] ?? 0;
        break;
      }

      case sqlTypes.SQL_BLOB: {
        const value = await channel.readExactly(8);
        value.copy(rowBuffer, column.offset);
        break;
      }

      case sqlTypes.SQL_NULL:
        break;

      default:
        throw new Error(`Unsupported Firebird column type ${column.type} while reading a cursor row.`);
    }
  }

  return rowBuffer;
}

export function buildPackedMessage(
  columns: readonly StatementColumn[],
  messageLength: number,
  message: Buffer | undefined,
): Buffer {
  const source = message ?? Buffer.alloc(messageLength);
  if (source.length !== messageLength) {
    throw new Error(`Incorrect statement input message length ${source.length}, expected ${messageLength}.`);
  }

  const view = new DataView(source.buffer, source.byteOffset, source.byteLength);
  const flagBytes = Math.ceil(columns.length / 8);
  const nullBitmap = Buffer.alloc(flagBytes);
  const writer = new XdrWriter();

  for (let index = 0; index < columns.length; index++) {
    if (view.getInt16(columns[index].nullOffset, LITTLE_ENDIAN) !== 0) {
      nullBitmap[index >> 3] |= 1 << (index & 7);
    }
  }

  writer.writeBytes(nullBitmap);
  writer.writeAlignment(nullBitmap.length);

  for (let index = 0; index < columns.length; index++) {
    if ((nullBitmap[index >> 3] & (1 << (index & 7))) !== 0) {
      continue;
    }

    const column = columns[index];
    switch (column.type) {
      case sqlTypes.SQL_VARYING: {
        const valueLength = view.getUint16(column.offset, LITTLE_ENDIAN);
        writer.writeInt32(valueLength);
        writer.writeBytes(source.subarray(column.offset + 2, column.offset + 2 + valueLength));
        writer.writeAlignment(valueLength);
        break;
      }

      case sqlTypes.SQL_DOUBLE: {
        const buffer = Buffer.alloc(8);
        buffer.writeDoubleBE(view.getFloat64(column.offset, LITTLE_ENDIAN), 0);
        writer.writeBytes(buffer);
        break;
      }

      case sqlTypes.SQL_TYPE_DATE:
      case sqlTypes.SQL_TYPE_TIME:
        writer.writeInt32(view.getInt32(column.offset, LITTLE_ENDIAN));
        break;

      case sqlTypes.SQL_TIME_TZ_EX:
        writer.writeInt32(view.getInt32(column.offset, LITTLE_ENDIAN));
        writer.writeInt32(view.getUint16(column.offset + 4, LITTLE_ENDIAN));
        writer.writeInt32(encodeTimeZoneOffset(view.getInt16(column.offset + 6, LITTLE_ENDIAN)));
        break;

      case sqlTypes.SQL_TIMESTAMP:
        writer.writeInt32(view.getInt32(column.offset, LITTLE_ENDIAN));
        writer.writeInt32(view.getInt32(column.offset + 4, LITTLE_ENDIAN));
        break;

      case sqlTypes.SQL_TIMESTAMP_TZ_EX:
        writer.writeInt32(view.getInt32(column.offset, LITTLE_ENDIAN));
        writer.writeInt32(view.getInt32(column.offset + 4, LITTLE_ENDIAN));
        writer.writeInt32(view.getUint16(column.offset + 8, LITTLE_ENDIAN));
        writer.writeInt32(view.getInt16(column.offset + 10, LITTLE_ENDIAN));
        break;

      case sqlTypes.SQL_BOOLEAN:
        writer.writeBytes(Buffer.from([source[column.offset] ?? 0]));
        writer.writeAlignment(1);
        break;

      case sqlTypes.SQL_BLOB:
        writer.writeBytes(source.subarray(column.offset, column.offset + 8));
        break;

      case sqlTypes.SQL_NULL:
        break;

      default:
        throw new Error(`Unsupported Firebird column type ${column.type} while encoding a packed message.`);
    }
  }

  return writer.toBuffer();
}

async function readPaddedOpaque(channel: SocketChannel, length: number): Promise<Buffer> {
  if (length === 0) {
    return Buffer.alloc(0);
  }

  const paddedLength = length + ((4 - (length % 4)) & 3);
  const value = await channel.readExactly(paddedLength);

  return value.subarray(0, length);
}

async function readXdrInt32(channel: SocketChannel): Promise<number> {
  return (await channel.readExactly(4)).readInt32BE(0);
}

function decodeTimeZoneValue(encodedValue: number): number {
  return encodedValue & 0xffff;
}

function decodeTimeZoneOffset(encodedValue: number): number {
  const value = decodeTimeZoneValue(encodedValue);
  return value - 1440;
}

function encodeTimeZoneOffset(offsetMinutes: number): number {
  return offsetMinutes + 1440;
}
