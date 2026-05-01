import { commonInfo, sqlTypes, statementInfo } from 'node-firebird-driver/dist/lib/impl';

import { blr } from './constants';
import { MutableStatementColumn, StatementColumn, StatementMetadata } from './protocol-types';

export function parseStatementMetadata(data: Buffer): StatementMetadata {
  const inputColumns: MutableStatementColumn[] = [];
  const outputColumns: MutableStatementColumn[] = [];
  let statementType = 0;
  let statementFlag = 0;
  let outputSection = false;
  let offset = 0;

  while (offset < data.length) {
    const item = data[offset++];
    if (item === commonInfo.end) {
      break;
    }

    switch (item) {
      case statementInfo.sqlStmtType:
        ({ value: statementType, nextOffset: offset } = readInfoNumeric(data, offset));
        break;

      case statementInfo.sqlStmtFlags:
        ({ value: statementFlag, nextOffset: offset } = readInfoNumeric(data, offset));
        break;

      case statementInfo.sqlSelect:
        outputSection = true;
        break;

      case statementInfo.sqlBind:
        outputSection = false;
        break;

      case statementInfo.sqlDescribeVars: {
        const describeInfo = readInfoNumeric(data, offset);
        offset = describeInfo.nextOffset;

        if (describeInfo.value === 0) {
          break;
        }

        let currentColumn: MutableStatementColumn | undefined;
        let remainingVariables = describeInfo.value;
        while (offset < data.length) {
          const describeItem = data[offset++];
          if (describeItem === statementInfo.sqlDescribeEnd) {
            currentColumn = undefined;
            if (--remainingVariables <= 0) {
              break;
            }

            continue;
          }

          if (
            describeItem === commonInfo.end ||
            describeItem === commonInfo.truncated ||
            describeItem === statementInfo.sqlSelect ||
            describeItem === statementInfo.sqlBind
          ) {
            offset--;
            break;
          }

          switch (describeItem) {
            case statementInfo.sqlSqldaSeq: {
              const sequenceInfo = readInfoNumeric(data, offset);
              const sequence = sequenceInfo.value;
              offset = sequenceInfo.nextOffset;
              const targetColumns = outputSection ? outputColumns : inputColumns;

              while (targetColumns.length < sequence) {
                targetColumns.push(createMutableStatementColumn());
              }

              currentColumn = targetColumns[sequence - 1];
              break;
            }

            case statementInfo.sqlType: {
              const typeInfo = readInfoNumeric(data, offset);
              const type = typeInfo.value;
              offset = typeInfo.nextOffset;
              if (currentColumn) {
                currentColumn.originalType = type & ~1;
                currentColumn.type = type & ~1;
                currentColumn.nullable = (type & 1) !== 0;
              }
              break;
            }

            case statementInfo.sqlSubType:
              if (currentColumn) {
                const info = readInfoNumeric(data, offset);
                currentColumn.subType = info.value;
                currentColumn.charSet = info.value;
                offset = info.nextOffset;
              } else {
                ({ nextOffset: offset } = readInfoNumeric(data, offset));
              }
              break;

            case statementInfo.sqlScale:
              if (currentColumn) {
                const info = readInfoNumeric(data, offset);
                currentColumn.scale = info.value;
                offset = info.nextOffset;
              } else {
                ({ nextOffset: offset } = readInfoNumeric(data, offset));
              }
              break;

            case statementInfo.sqlLength:
              if (currentColumn) {
                const info = readInfoNumeric(data, offset);
                currentColumn.length = info.value;
                offset = info.nextOffset;
              } else {
                ({ nextOffset: offset } = readInfoNumeric(data, offset));
              }
              break;

            case statementInfo.sqlField:
              if (currentColumn) {
                const info = readInfoString(data, offset);
                currentColumn.field = info.value;
                offset = info.nextOffset;
              } else {
                ({ nextOffset: offset } = readInfoString(data, offset));
              }
              break;

            case statementInfo.sqlRelation:
              if (currentColumn) {
                const info = readInfoString(data, offset);
                currentColumn.relation = info.value;
                offset = info.nextOffset;
              } else {
                ({ nextOffset: offset } = readInfoString(data, offset));
              }
              break;

            case statementInfo.sqlAlias:
              if (currentColumn) {
                const info = readInfoString(data, offset);
                currentColumn.alias = info.value;
                offset = info.nextOffset;
              } else {
                ({ nextOffset: offset } = readInfoString(data, offset));
              }
              break;

            default:
              ({ nextOffset: offset } = readInfoString(data, offset));
              break;
          }
        }
        break;
      }

      default:
        ({ nextOffset: offset } = readInfoString(data, offset));
        break;
    }
  }

  const normalizedInputColumns = normalizeColumns(inputColumns);
  const normalizedOutputColumns = normalizeColumns(outputColumns);
  const inputFormat = buildMessageFormat(normalizedInputColumns);
  const outputFormat = buildMessageFormat(normalizedOutputColumns);

  return {
    type: statementType,
    flags: statementFlag,
    inputColumns: normalizedInputColumns,
    outputColumns: normalizedOutputColumns,
    inputBlr: inputFormat.blr,
    inputMessageLength: inputFormat.messageLength,
    outputBlr: outputFormat.blr,
    outputMessageLength: outputFormat.messageLength,
  };
}

function createMutableStatementColumn(): MutableStatementColumn {
  return {
    alias: '',
    field: '',
    relation: '',
    type: 0,
    originalType: 0,
    subType: 0,
    charSet: 0,
    scale: 0,
    length: 0,
    nullable: false,
    offset: 0,
    nullOffset: 0,
  };
}

function readInfoNumeric(data: Buffer, offset: number): { value: number; nextOffset: number } {
  if (offset + 2 > data.length) {
    return { value: 0, nextOffset: data.length };
  }

  const length = data.readUInt16LE(offset);
  const valueOffset = offset + 2;

  return {
    value: readLittleEndianInteger(data, valueOffset, length),
    nextOffset: Math.min(valueOffset + length, data.length),
  };
}

function readInfoString(data: Buffer, offset: number): { value: string; nextOffset: number } {
  if (offset + 2 > data.length) {
    return { value: '', nextOffset: data.length };
  }

  const length = data.readUInt16LE(offset);
  const valueOffset = offset + 2;
  const endOffset = Math.min(valueOffset + length, data.length);

  return {
    value: data.subarray(valueOffset, endOffset).toString('utf8'),
    nextOffset: endOffset,
  };
}

function readLittleEndianInteger(buffer: Buffer, offset: number, length: number): number {
  let value = 0;
  for (let i = 0; i < length; i++) {
    value += buffer[offset + i] << (8 * i);
  }

  if (length > 0 && (buffer[offset + length - 1] & 0x80) !== 0) {
    value -= 2 ** (length * 8);
  }

  return value;
}

function normalizeColumns(columns: readonly MutableStatementColumn[]): MutableStatementColumn[] {
  return columns.map((column) => {
    const normalized = { ...column };

    switch (normalized.type) {
      case sqlTypes.SQL_TEXT:
        normalized.type = sqlTypes.SQL_VARYING;
        break;

      case sqlTypes.SQL_SHORT:
      case sqlTypes.SQL_LONG:
      case sqlTypes.SQL_INT64:
      case sqlTypes.SQL_FLOAT:
        normalized.type = sqlTypes.SQL_DOUBLE;
        normalized.subType = 0;
        normalized.scale = 0;
        normalized.length = 8;
        break;

      case sqlTypes.SQL_TIME_TZ:
        normalized.type = sqlTypes.SQL_TIME_TZ_EX;
        normalized.subType = 0;
        normalized.length = 8;
        break;

      case sqlTypes.SQL_TIMESTAMP_TZ:
        normalized.type = sqlTypes.SQL_TIMESTAMP_TZ_EX;
        normalized.subType = 0;
        normalized.length = 12;
        break;

      case sqlTypes.SQL_INT128:
      case sqlTypes.SQL_DEC16:
      case sqlTypes.SQL_DEC34:
        normalized.type = sqlTypes.SQL_VARYING;
        normalized.subType = 2;
        normalized.charSet = 2;
        normalized.scale = 0;
        normalized.length = 45;
        break;
    }

    if (normalized.type !== sqlTypes.SQL_TEXT && normalized.type !== sqlTypes.SQL_VARYING) {
      normalized.charSet = 0;
    }

    return normalized;
  });
}

function buildMessageFormat(columns: MutableStatementColumn[]): { blr: Buffer; messageLength: number } {
  let messageLength = 0;
  const fieldCount = columns.length * 2;
  const parts = [blr.version5, blr.begin, blr.message, 0, fieldCount & 0xff, (fieldCount >> 8) & 0xff];

  for (const column of columns) {
    const { blr: columnBlr, alignment, length } = describeColumnType(column);
    if (alignment > 1) {
      messageLength = align(messageLength, alignment);
    }

    const offset = messageLength;
    messageLength += length;
    const nullOffset = align(messageLength, 2);
    messageLength = nullOffset + 2;

    column.offset = offset;
    column.nullOffset = nullOffset;

    parts.push(...columnBlr, blr.short, 0);
  }

  parts.push(blr.end, blr.eoc);
  return { blr: Buffer.from(parts), messageLength };
}

function describeColumnType(column: StatementColumn): { blr: number[]; alignment: number; length: number } {
  switch (column.type) {
    case sqlTypes.SQL_TEXT:
      return {
        blr: [
          blr.text2,
          column.charSet & 0xff,
          (column.charSet >> 8) & 0xff,
          column.length & 0xff,
          (column.length >> 8) & 0xff,
        ],
        alignment: 1,
        length: column.length,
      };
    case sqlTypes.SQL_VARYING:
      return {
        blr: [
          blr.varying2,
          column.charSet & 0xff,
          (column.charSet >> 8) & 0xff,
          column.length & 0xff,
          (column.length >> 8) & 0xff,
        ],
        alignment: 2,
        length: column.length + 2,
      };
    case sqlTypes.SQL_SHORT:
      return { blr: [blr.short, column.scale & 0xff], alignment: 2, length: 2 };
    case sqlTypes.SQL_LONG:
      return { blr: [blr.long, column.scale & 0xff], alignment: 4, length: 4 };
    case sqlTypes.SQL_INT64:
      return { blr: [blr.int64, column.scale & 0xff], alignment: 8, length: 8 };
    case sqlTypes.SQL_DOUBLE:
      return { blr: [blr.double], alignment: 8, length: 8 };
    case sqlTypes.SQL_TIMESTAMP:
      return { blr: [blr.timestamp], alignment: 4, length: 8 };
    case sqlTypes.SQL_TYPE_DATE:
      return { blr: [blr.sqlDate], alignment: 4, length: 4 };
    case sqlTypes.SQL_TYPE_TIME:
      return { blr: [blr.sqlTime], alignment: 4, length: 4 };
    case sqlTypes.SQL_TIME_TZ_EX:
      return { blr: [blr.exTimeTz], alignment: 4, length: 8 };
    case sqlTypes.SQL_BOOLEAN:
      return { blr: [blr.bool], alignment: 1, length: 1 };
    case sqlTypes.SQL_BLOB:
      return {
        blr: [blr.blob2, column.subType & 0xff, (column.subType >> 8) & 0xff, 0, 0],
        alignment: 4,
        length: 8,
      };
    case sqlTypes.SQL_TIMESTAMP_TZ_EX:
      return { blr: [blr.exTimestampTz], alignment: 4, length: 12 };
    case sqlTypes.SQL_NULL:
      return { blr: [blr.null_], alignment: 1, length: 0 };
    default:
      throw new Error(`Unsupported Firebird column type ${column.type} for cursor fetch.`);
  }
}

function align(value: number, alignment: number): number {
  return alignment > 1 ? (value + alignment - 1) & ~(alignment - 1) : value;
}
