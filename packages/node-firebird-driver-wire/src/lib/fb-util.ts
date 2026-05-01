import { Descriptor } from 'node-firebird-driver/dist/lib/impl';
import { StatementColumn } from './wire-protocol';

export * from 'node-firebird-driver/dist/lib/impl';

export function createDescriptors(columns: readonly StatementColumn[]): Descriptor[] {
  return columns.map((column) => ({
    type: column.type,
    subType: column.subType,
    charSet: column.charSet,
    length: column.length,
    scale: column.scale,
    offset: column.offset,
    nullOffset: column.nullOffset,
  }));
}
