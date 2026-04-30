import { Buffer } from 'node:buffer';
import { connect as connectSocket, Socket } from 'node:net';
import { endianness, hostname, userInfo } from 'node:os';

import { commonInfo, dpb, epb, sqlTypes, statementInfo } from 'node-firebird-driver/dist/lib/impl';

import { ClientAuthPlugin, createAuthPlugin } from './auth/plugins';
import {
  authPlugin,
  blr,
  connectParameter,
  dsql,
  protocolRequest,
  statementFlag,
  wireCrypt,
  wireOp,
  wirePacketType,
  wireProtocol,
} from './constants';
import { SocketChannel } from './socket-channel';
import { assertSuccessfulResponse, parseStatusVector } from './status';
import { createWireCryptSession } from './wire-crypt';
import { writeTraditionalClumplet, writeWideClumplet, writeWideStringClumplet, XdrWriter } from './xdr';

const { list: AUTH_PLUGINS } = authPlugin;
type AuthPluginName = authPlugin.Name;

// FIXME:
const {
  begin: blr_begin,
  blob2: blr_blob2,
  bool: blr_bool,
  double: blr_double,
  end: blr_end,
  eoc: blr_eoc,
  exTimeTz: blr_ex_time_tz,
  exTimestampTz: blr_ex_timestamp_tz,
  int64: blr_int64,
  long: blr_long,
  message: blr_message,
  null_: blr_null,
  short: blr_short,
  sqlDate: blr_sql_date,
  sqlTime: blr_sql_time,
  text: blr_text,
  timestamp: blr_timestamp,
  varying: blr_varying,
  version5: blr_version5,
} = blr;

// FIXME:
const {
  clientCrypt: CNCT_client_crypt,
  host: CNCT_host,
  login: CNCT_login,
  pluginList: CNCT_plugin_list,
  pluginName: CNCT_plugin_name,
  specificData: CNCT_specific_data,
  user: CNCT_user,
  userVerification: CNCT_user_verification,
} = connectParameter;

// FIXME:
const { async: P_REQ_async } = protocolRequest;
const { hasCursor: STATEMENT_FLAG_HAS_CURSOR } = statementFlag;
const { enabled: WIRE_CRYPT_ENABLED } = wireCrypt;

// FIXME:
const {
  accept: op_accept,
  acceptData: op_accept_data,
  allocateStatement: op_allocate_statement,
  attach: op_attach,
  cancel: op_cancel,
  cancelBlob: op_cancel_blob,
  cancelEvents: op_cancel_events,
  closeBlob: op_close_blob,
  commit: op_commit,
  commitRetaining: op_commit_retaining,
  condAccept: op_cond_accept,
  connect: op_connect,
  connectRequest: op_connect_request,
  crypt: op_crypt,
  contAuth: op_cont_auth,
  create: op_create,
  createBlob2: op_create_blob2,
  detach: op_detach,
  disconnect: op_disconnect,
  dropDatabase: op_drop_database,
  dummy: op_dummy,
  event: op_event,
  execute: op_execute,
  execute2: op_execute2,
  fetch: op_fetch,
  fetchResponse: op_fetch_response,
  freeStatement: op_free_statement,
  getSegment: op_get_segment,
  infoBlob: op_info_blob,
  infoSql: op_info_sql,
  openBlob2: op_open_blob2,
  ping: op_ping,
  prepareStatement: op_prepare_statement,
  putSegment: op_put_segment,
  queEvents: op_que_events,
  reject: op_reject,
  response: op_response,
  rollback: op_rollback,
  rollbackRetaining: op_rollback_retaining,
  seekBlob: op_seek_blob,
  setCursor: op_set_cursor,
  sqlResponse: op_sql_response,
  transaction: op_transaction,
} = wireOp;

// FIXME:
const { batchSend: ptype_batch_send } = wirePacketType;
const {
  archGeneric: arch_generic,
  connectVersion3: CONNECT_VERSION3,
  supportedProtocols: SUPPORTED_PROTOCOLS,
} = wireProtocol;

export interface WireProtocolOptions {
  readonly host: string;
  readonly port?: number;
  readonly username: string;
  readonly password: string;
  readonly timeoutMs?: number;
}

export interface AttachmentHandle {
  readonly handle: number;
}

export interface TransactionHandle {
  readonly handle: number;
}

export interface StatementHandle {
  readonly handle: number;
}

export interface BlobHandle {
  readonly handle: number;
  readonly id: Buffer;
}

export interface BlobSegmentResponse {
  readonly state: number;
  readonly data: Buffer;
}

export interface StatementColumn {
  readonly alias: string;
  readonly field: string;
  readonly relation: string;
  readonly type: number;
  readonly originalType: number;
  readonly subType: number;
  readonly charSet: number;
  readonly scale: number;
  readonly length: number;
  readonly nullable: boolean;
  readonly offset: number;
  readonly nullOffset: number;
}

export interface CursorHandle {
  readonly statement: StatementHandle;
  readonly columns: readonly StatementColumn[];
  readonly fetchBlr: Buffer;
  readonly fetchMessageLength: number;
}

export interface EventHandle {
  readonly id: number;
  readonly names: readonly string[];
}

type EventCallback = (counters: [string, number][]) => Promise<void> | void;

interface AcceptMessage {
  readonly authenticated: boolean;
  readonly pluginName: string;
  readonly data: Buffer;
  readonly keys: Buffer;
}

interface ResponseMessage {
  readonly handle: number;
  readonly objectId: bigint;
  readonly quad: Buffer;
  readonly data: Buffer;
  readonly status: ReturnType<typeof parseStatusVector>;
}

interface DpbClumplet {
  readonly tag: number;
  readonly value: Buffer;
}

interface StatementMetadata {
  readonly type: number;
  readonly flags: number;
  readonly inputColumns: readonly StatementColumn[];
  readonly outputColumns: readonly StatementColumn[];
  readonly inputBlr: Buffer;
  readonly inputMessageLength: number;
  readonly outputBlr: Buffer;
  readonly outputMessageLength: number;
}

interface MutableStatementColumn {
  alias: string;
  field: string;
  relation: string;
  type: number;
  originalType: number;
  subType: number;
  charSet: number;
  scale: number;
  length: number;
  nullable: boolean;
  offset: number;
  nullOffset: number;
}

interface EventMessage {
  readonly database: number;
  readonly items: Buffer;
  readonly requestId: number;
}

interface EventSubscription {
  readonly id: number;
  readonly names: readonly string[];
  readonly callback: EventCallback;
  eventBuffer: Buffer;
}

const LITTLE_ENDIAN = endianness() === 'LE';
const FETCH_NO_DATA = 100;

const STATEMENT_BASE_INFO_ITEMS = Buffer.from([statementInfo.sqlStmtType, statementInfo.sqlStmtFlags]);
const STATEMENT_SELECT_INFO_ITEMS = Buffer.from([
  statementInfo.sqlSelect,
  statementInfo.sqlDescribeVars,
  statementInfo.sqlSqldaSeq,
  statementInfo.sqlType,
  statementInfo.sqlSubType,
  statementInfo.sqlScale,
  statementInfo.sqlLength,
  statementInfo.sqlField,
  statementInfo.sqlAlias,
  statementInfo.sqlRelation,
  statementInfo.sqlRelationAlias,
  statementInfo.sqlOwner,
  statementInfo.sqlDescribeEnd,
]);
const STATEMENT_BIND_INFO_ITEMS = Buffer.from([
  statementInfo.sqlBind,
  statementInfo.sqlDescribeVars,
  statementInfo.sqlSqldaSeq,
  statementInfo.sqlType,
  statementInfo.sqlSubType,
  statementInfo.sqlScale,
  statementInfo.sqlLength,
  statementInfo.sqlDescribeEnd,
]);
const INFO_BUFFER_LENGTH = 32767;

export class WireProtocol {
  private socket?: Socket;
  private channel?: SocketChannel;
  private eventSocket?: Socket;
  private eventChannel?: SocketChannel;
  private eventLoopPromise?: Promise<void>;
  private mainChannelQueue: Promise<void> = Promise.resolve();
  private attachmentHandle?: number;
  private currentPluginName: AuthPluginName = 'Legacy_Auth';
  private currentPlugin?: ClientAuthPlugin;
  private clientAuthListSent = false;
  private wireCryptEnabled = false;
  private readonly pendingServerKeys: Buffer[] = [];
  private readonly statementMetadata = new Map<number, StatementMetadata>();
  private readonly exhaustedCursors = new Set<number>();
  private readonly eventSubscriptions = new Map<number, EventSubscription>();
  private nextEventId = 1;

  constructor(private readonly options: WireProtocolOptions) {}

  async attach(database: string, dpb: Buffer): Promise<AttachmentHandle> {
    return await this.runMainChannelTask(async () => {
      if (this.attachmentHandle) {
        throw new Error('A database is already attached on this protocol instance.');
      }

      await this.openSocket();
      const attachAuthData = await this.performConnectHandshake(database);
      return await this.executeAttachmentOperation(op_attach, database, dpb, attachAuthData, 'attach');
    });
  }

  async createDatabase(database: string, dpb: Buffer): Promise<AttachmentHandle> {
    return await this.runMainChannelTask(async () => {
      if (this.attachmentHandle) {
        throw new Error('A database is already attached on this protocol instance.');
      }

      await this.openSocket();
      const attachAuthData = await this.performConnectHandshake(database);
      return await this.executeAttachmentOperation(op_create, database, dpb, attachAuthData, 'create');
    });
  }

  async detach(attachment: AttachmentHandle): Promise<void> {
    await this.runMainChannelTask(async () => {
      if (this.attachmentHandle !== attachment.handle) {
        throw new Error('Attachment handle is not active.');
      }

      const writer = new XdrWriter();
      writer.writeInt32(op_detach);
      writer.writeInt32(0);
      await this.channel!.write(writer.toBuffer());

      const operation = await this.readOperation();
      if (operation !== op_response) {
        throw new Error(`Unexpected operation ${operation} while detaching.`);
      }

      const response = await this.readResponse();
      assertSuccessfulResponse(response.status, 'Firebird detach failed');
      this.attachmentHandle = undefined;
    });
  }

  async dropDatabase(attachment: AttachmentHandle): Promise<void> {
    await this.runMainChannelTask(async () => {
      if (this.attachmentHandle !== attachment.handle) {
        throw new Error('Attachment handle is not active.');
      }

      const writer = new XdrWriter();
      writer.writeInt32(op_drop_database);
      writer.writeInt32(0);
      await this.channel!.write(writer.toBuffer());

      const operation = await this.readOperation();
      if (operation !== op_response) {
        throw new Error(`Unexpected operation ${operation} while dropping the database.`);
      }

      const response = await this.readResponse();
      assertSuccessfulResponse(response.status, 'Firebird drop database failed');
      this.attachmentHandle = undefined;
    });
  }

  async ping(): Promise<void> {
    await this.runMainChannelTask(async () => {
      if (!this.channel) {
        throw new Error('Wire protocol socket is not open.');
      }

      const writer = new XdrWriter();
      writer.writeInt32(op_ping);
      await this.channel.write(writer.toBuffer());

      const operation = await this.readOperation();
      if (operation !== op_response) {
        throw new Error(`Unexpected operation ${operation} while pinging.`);
      }

      const response = await this.readResponse();
      assertSuccessfulResponse(response.status, 'Firebird ping failed');
    });
  }

  async queueEvents(names: readonly string[], callback: EventCallback): Promise<EventHandle> {
    return await this.runMainChannelTask(async () => {
      if (!this.channel || this.attachmentHandle == undefined) {
        throw new Error('A database must be attached before queueing events.');
      }

      await this.ensureEventChannel();

      const eventHandle: EventHandle = {
        id: this.nextEventId++,
        names: [...names],
      };

      const subscription: EventSubscription = {
        ...eventHandle,
        callback,
        eventBuffer: this.buildEventBlock(names),
      };
      this.eventSubscriptions.set(eventHandle.id, subscription);

      try {
        await this.sendQueueEvents(subscription);
        return eventHandle;
      } catch (error) {
        this.eventSubscriptions.delete(subscription.id);
        throw error;
      }
    });
  }

  async cancelEvents(event: EventHandle): Promise<void> {
    await this.runMainChannelTask(async () => {
      const subscription = this.eventSubscriptions.get(event.id);
      if (!subscription) {
        return;
      }

      this.eventSubscriptions.delete(event.id);

      if (!this.channel || this.attachmentHandle == undefined) {
        return;
      }

      const writer = new XdrWriter();
      writer.writeInt32(op_cancel_events);
      writer.writeInt32(0);
      writer.writeInt32(event.id);
      await this.channel.write(writer.toBuffer());

      const operation = await this.readOperation();
      if (operation !== op_response) {
        throw new Error(`Unexpected operation ${operation} while cancelling events.`);
      }

      const response = await this.readResponse();
      assertSuccessfulResponse(response.status, 'Firebird cancel events failed');
    });
  }

  // FIXME: kind?
  async cancelOperation(kind: number): Promise<void> {
    if (!this.channel) {
      throw new Error('Wire protocol socket is not open.');
    }

    if (kind === 4) {
      await this.close();
      return;
    }

    const writer = new XdrWriter();
    writer.writeInt32(op_cancel);
    writer.writeInt32(kind);
    await this.channel.write(writer.toBuffer());
  }

  async startTransaction(tpb: Buffer): Promise<TransactionHandle> {
    return await this.runMainChannelTask(async () => {
      if (!this.channel || this.attachmentHandle == undefined) {
        throw new Error('A database must be attached before starting a transaction.');
      }

      const writer = new XdrWriter();
      writer.writeInt32(op_transaction);
      writer.writeInt32(0);
      writer.writeBuffer(tpb);
      await this.channel.write(writer.toBuffer());

      const operation = await this.readOperation();
      if (operation !== op_response) {
        throw new Error(`Unexpected operation ${operation} while starting a transaction.`);
      }

      const response = await this.readResponse();
      assertSuccessfulResponse(response.status, 'Firebird start transaction failed');
      return { handle: response.handle };
    });
  }

  async commit(transaction: TransactionHandle): Promise<void> {
    await this.runMainChannelTask(async () => {
      await this.finishTransaction(op_commit, transaction, 'commit');
    });
  }

  async rollback(transaction: TransactionHandle): Promise<void> {
    await this.runMainChannelTask(async () => {
      await this.finishTransaction(op_rollback, transaction, 'rollback');
    });
  }

  async commitRetaining(transaction: TransactionHandle): Promise<void> {
    await this.runMainChannelTask(async () => {
      await this.finishTransaction(op_commit_retaining, transaction, 'commit retaining');
    });
  }

  async rollbackRetaining(transaction: TransactionHandle): Promise<void> {
    await this.runMainChannelTask(async () => {
      await this.finishTransaction(op_rollback_retaining, transaction, 'rollback retaining');
    });
  }

  async createBlob(transaction: TransactionHandle, bpb: Uint8Array = Buffer.alloc(0)): Promise<BlobHandle> {
    return await this.runMainChannelTask(async () => {
      return await this.openOrCreateBlob(op_create_blob2, transaction, Buffer.alloc(8), bpb, 'create blob');
    });
  }

  async openBlob(
    transaction: TransactionHandle,
    blobId: Uint8Array,
    bpb: Uint8Array = Buffer.alloc(0),
  ): Promise<BlobHandle> {
    return await this.runMainChannelTask(async () => {
      return await this.openOrCreateBlob(op_open_blob2, transaction, blobId, bpb, 'open blob');
    });
  }

  async getSegment(blob: BlobHandle, bufferLength: number): Promise<BlobSegmentResponse> {
    return await this.runMainChannelTask(async () => {
      if (!this.channel || this.attachmentHandle == undefined) {
        throw new Error('A database must be attached before reading a blob segment.');
      }

      const writer = new XdrWriter();
      writer.writeInt32(op_get_segment);
      writer.writeInt32(blob.handle);
      writer.writeInt32(bufferLength);
      writer.writeBuffer(Buffer.alloc(0));
      await this.channel.write(writer.toBuffer());

      const operation = await this.readOperation();
      if (operation !== op_response) {
        throw new Error(`Unexpected operation ${operation} while getting a blob segment.`);
      }

      const response = await this.readResponse();
      assertSuccessfulResponse(response.status, 'Firebird get blob segment failed');
      return {
        state: response.handle,
        data: response.data,
      };
    });
  }

  async putSegment(blob: BlobHandle, segment: Buffer): Promise<void> {
    await this.runMainChannelTask(async () => {
      if (!this.channel || this.attachmentHandle == undefined) {
        throw new Error('A database must be attached before writing a blob segment.');
      }

      const writer = new XdrWriter();
      writer.writeInt32(op_put_segment);
      writer.writeInt32(blob.handle);
      writer.writeInt32(segment.length);
      writer.writeBuffer(segment);
      await this.channel.write(writer.toBuffer());

      const operation = await this.readOperation();
      if (operation !== op_response) {
        throw new Error(`Unexpected operation ${operation} while putting a blob segment.`);
      }

      const response = await this.readResponse();
      assertSuccessfulResponse(response.status, 'Firebird put blob segment failed');
    });
  }

  async seekBlob(blob: BlobHandle, mode: number, offset: number): Promise<number> {
    return await this.runMainChannelTask(async () => {
      if (!this.channel || this.attachmentHandle == undefined) {
        throw new Error('A database must be attached before seeking a blob.');
      }

      const writer = new XdrWriter();
      writer.writeInt32(op_seek_blob);
      writer.writeInt32(blob.handle);
      writer.writeInt32(mode);
      writer.writeInt32(offset);
      await this.channel.write(writer.toBuffer());

      const operation = await this.readOperation();
      if (operation !== op_response) {
        throw new Error(`Unexpected operation ${operation} while seeking a blob.`);
      }

      const response = await this.readResponse();
      assertSuccessfulResponse(response.status, 'Firebird seek blob failed');
      return response.handle !== 0 ? response.handle : response.quad.readInt32BE(4);
    });
  }

  async closeBlob(blob: BlobHandle): Promise<void> {
    await this.runMainChannelTask(async () => {
      await this.finishBlob(op_close_blob, blob, 'close blob');
    });
  }

  async cancelBlob(blob: BlobHandle): Promise<void> {
    await this.runMainChannelTask(async () => {
      await this.finishBlob(op_cancel_blob, blob, 'cancel blob');
    });
  }

  async allocateStatement(): Promise<StatementHandle> {
    return await this.runMainChannelTask(async () => {
      if (!this.channel || this.attachmentHandle == undefined) {
        throw new Error('A database must be attached before allocating a statement.');
      }

      const writer = new XdrWriter();
      writer.writeInt32(op_allocate_statement);
      writer.writeInt32(this.attachmentHandle);
      await this.channel.write(writer.toBuffer());

      const operation = await this.readOperation();
      if (operation !== op_response) {
        throw new Error(`Unexpected operation ${operation} while allocating a statement.`);
      }

      const response = await this.readResponse();
      assertSuccessfulResponse(response.status, 'Firebird allocate statement failed');
      return { handle: response.handle };
    });
  }

  async prepareStatement(
    transaction: TransactionHandle,
    statement: StatementHandle,
    sql: string,
    sqlDialect = 3,
  ): Promise<void> {
    await this.runMainChannelTask(async () => {
      if (!this.channel || this.attachmentHandle == undefined) {
        throw new Error('A database must be attached before preparing a statement.');
      }

      const writer = new XdrWriter();
      writer.writeInt32(op_prepare_statement);
      writer.writeInt32(transaction.handle);
      writer.writeInt32(statement.handle);
      writer.writeInt32(sqlDialect);
      writer.writeString(sql);
      writer.writeBuffer(STATEMENT_BASE_INFO_ITEMS);
      writer.writeInt32(INFO_BUFFER_LENGTH);
      await this.channel.write(writer.toBuffer());

      const operation = await this.readOperation();
      if (operation !== op_response) {
        throw new Error(`Unexpected operation ${operation} while preparing a statement.`);
      }

      const response = await this.readResponse();
      assertSuccessfulResponse(response.status, 'Firebird prepare statement failed');

      // FIXME: Why two calls?
      const selectInfo = await this.getInfo(
        op_info_sql,
        statement.handle,
        STATEMENT_SELECT_INFO_ITEMS,
        'statement output metadata',
      );
      const bindInfo = await this.getInfo(
        op_info_sql,
        statement.handle,
        STATEMENT_BIND_INFO_ITEMS,
        'statement input metadata',
      );

      const metadataInfo = this.concatInfoBuffers([response.data, selectInfo, bindInfo]);
      this.statementMetadata.set(statement.handle, this.parseStatementMetadata(metadataInfo));
    });
  }

  async executeStatement(
    transaction: TransactionHandle,
    statement: StatementHandle,
    inputMessage?: Buffer,
  ): Promise<Buffer | undefined> {
    return await this.runMainChannelTask(async () => {
      return await this.executePreparedStatement(transaction, statement, inputMessage, false);
    });
  }

  async executeStatementReturning(
    transaction: TransactionHandle,
    statement: StatementHandle,
    inputMessage?: Buffer,
  ): Promise<Buffer | undefined> {
    return await this.runMainChannelTask(async () => {
      return await this.executePreparedStatement(transaction, statement, inputMessage, true);
    });
  }

  async setCursorName(statement: StatementHandle, cursorName: string): Promise<void> {
    await this.runMainChannelTask(async () => {
      if (!this.channel || this.attachmentHandle == undefined) {
        throw new Error('A database must be attached before setting a cursor name.');
      }

      const writer = new XdrWriter();
      writer.writeInt32(op_set_cursor);
      writer.writeInt32(statement.handle);
      writer.writeString(cursorName);
      writer.writeInt32(0);
      await this.channel.write(writer.toBuffer());

      const operation = await this.readOperation();
      if (operation !== op_response) {
        throw new Error(`Unexpected operation ${operation} while setting a cursor name.`);
      }

      const response = await this.readResponse();
      assertSuccessfulResponse(response.status, 'Firebird set cursor name failed');
    });
  }

  async getSqlInfo(statement: StatementHandle, items: Buffer): Promise<Buffer> {
    return await this.runMainChannelTask(async () => {
      return await this.getInfo(op_info_sql, statement.handle, items, 'sql info');
    });
  }

  async getBlobInfo(blob: BlobHandle, items: Buffer): Promise<Buffer> {
    return await this.runMainChannelTask(async () => {
      return await this.getInfo(op_info_blob, blob.handle, items, 'blob info');
    });
  }

  getStatementMetadata(statement: StatementHandle): StatementMetadata {
    const metadata = this.statementMetadata.get(statement.handle);
    if (!metadata) {
      throw new Error('Statement metadata is not available.');
    }

    return metadata;
  }

  async openCursor(
    transaction: TransactionHandle,
    statement: StatementHandle,
    inputMessage?: Buffer,
  ): Promise<CursorHandle> {
    return await this.runMainChannelTask(async () => {
      const metadata = this.getStatementMetadata(statement);

      if ((metadata.flags & STATEMENT_FLAG_HAS_CURSOR) === 0) {
        throw new Error('Statement does not produce a cursor.');
      }

      await this.executePreparedStatement(transaction, statement, inputMessage, false);
      this.exhaustedCursors.delete(statement.handle);

      return {
        statement,
        columns: metadata.outputColumns,
        fetchBlr: metadata.outputBlr,
        fetchMessageLength: metadata.outputMessageLength,
      };
    });
  }

  async fetchNext(cursor: CursorHandle): Promise<Buffer | undefined> {
    return await this.runMainChannelTask(async () => {
      if (!this.channel || this.attachmentHandle == undefined) {
        throw new Error('A database must be attached before fetching from a cursor.');
      }

      const metadata = this.statementMetadata.get(cursor.statement.handle);
      if (!metadata) {
        throw new Error('Statement metadata is not available for cursor fetch.');
      }

      if (this.exhaustedCursors.has(cursor.statement.handle)) {
        return undefined;
      }

      const writer = new XdrWriter();
      writer.writeInt32(op_fetch);
      writer.writeInt32(cursor.statement.handle);
      writer.writeBuffer(cursor.fetchBlr);
      writer.writeInt32(0);
      writer.writeInt32(1);
      await this.channel.write(writer.toBuffer());

      const operation = await this.readOperation();
      if (operation === op_response) {
        const response = await this.readResponse();
        assertSuccessfulResponse(response.status, 'Firebird fetch cursor row failed');
        return undefined;
      }

      if (operation !== op_fetch_response) {
        throw new Error(`Unexpected operation ${operation} while fetching a cursor row.`);
      }

      const status = (await this.channel.readExactly(4)).readInt32BE(0);
      const messages = (await this.channel.readExactly(4)).readInt32BE(0);

      if (messages === 0) {
        if (status === FETCH_NO_DATA) {
          this.exhaustedCursors.add(cursor.statement.handle);
          return undefined;
        }

        if (status === 0) {
          return undefined;
        }

        throw new Error(`Firebird cursor fetch failed with status ${status}.`);
      }

      if (messages !== 1) {
        throw new Error(`Unsupported cursor fetch batch size ${messages}.`);
      }

      const rowBuffer = await this.readPackedMessageBuffer(metadata.outputColumns, metadata.outputMessageLength);
      await this.readFetchBatchMarker(cursor.statement.handle);
      return rowBuffer;
    });
  }

  async closeCursor(statement: StatementHandle): Promise<void> {
    await this.runMainChannelTask(async () => {
      await this.finishStatement(statement, dsql.close, 'close cursor');
    });
  }

  async freeStatement(statement: StatementHandle): Promise<void> {
    await this.runMainChannelTask(async () => {
      await this.finishStatement(statement, dsql.drop, 'free statement');
    });
  }

  async close(): Promise<void> {
    if (this.eventSocket) {
      const eventSocket = this.eventSocket;
      this.eventChannel = undefined;
      this.eventSocket = undefined;
      eventSocket.destroy();
    }

    if (this.channel) {
      const writer = new XdrWriter();
      writer.writeInt32(op_disconnect);
      await this.channel.write(writer.toBuffer()).catch(() => undefined);
    }

    if (this.socket) {
      const socket = this.socket;
      await new Promise<void>((resolve) => {
        let settled = false;

        const finish = () => {
          if (settled) {
            return;
          }

          settled = true;
          socket.off('close', onClose);
          clearTimeout(destroyTimer);
          resolve();
        };

        const onClose = () => finish();

        const destroyTimer = setTimeout(() => {
          socket.destroy();
          finish();
        }, this.options.timeoutMs ?? 5000);

        destroyTimer.unref();

        socket.once('close', onClose);
        socket.end();
      }).catch(() => undefined);
    }

    this.channel = undefined;
    this.socket = undefined;
    this.attachmentHandle = undefined;
    this.wireCryptEnabled = false;
    this.pendingServerKeys.length = 0;
    this.eventSubscriptions.clear();
  }

  private async openSocket(): Promise<void> {
    if (this.socket) {
      return;
    }

    const socket = connectSocket({
      host: this.options.host,
      port: this.options.port ?? 3050,
      timeout: this.options.timeoutMs ?? 5000,
    });

    await new Promise<void>((resolve, reject) => {
      socket.once('connect', () => resolve());
      socket.once('error', (error) => reject(error));
      socket.once('timeout', () => reject(new Error('Firebird socket connection timed out.')));
    });

    this.socket = socket;
    this.channel = new SocketChannel(socket);
  }

  private async runMainChannelTask<T>(task: () => Promise<T>): Promise<T> {
    const previous = this.mainChannelQueue;
    let release: () => void = undefined!;
    this.mainChannelQueue = new Promise<void>((resolve) => {
      release = resolve;
    });

    await previous;

    try {
      return await task();
    } finally {
      release();
    }
  }

  private async ensureEventChannel(): Promise<void> {
    if (this.eventChannel) {
      return;
    }

    if (!this.channel || this.attachmentHandle == undefined || !this.socket) {
      throw new Error('A database must be attached before opening the event channel.');
    }

    const writer = new XdrWriter();
    writer.writeInt32(op_connect_request);
    writer.writeInt32(P_REQ_async);
    writer.writeInt32(0);
    writer.writeInt32(0);
    await this.channel.write(writer.toBuffer());

    const operation = await this.readOperation();
    if (operation !== op_response) {
      throw new Error(`Unexpected operation ${operation} while opening the event channel.`);
    }

    const response = await this.readResponse();
    assertSuccessfulResponse(response.status, 'Firebird open event channel failed');

    const eventPort = this.parseAuxiliaryPort(response.data);
    const eventHost = this.getEventHost();
    const eventSocket = connectSocket({
      host: eventHost,
      port: eventPort,
      timeout: this.options.timeoutMs ?? 5000,
    });

    await new Promise<void>((resolve, reject) => {
      eventSocket.once('connect', () => resolve());
      eventSocket.once('error', (error) => reject(error));
      eventSocket.once('timeout', () => reject(new Error('Firebird event socket connection timed out.')));
    });

    this.eventSocket = eventSocket;
    this.eventChannel = new SocketChannel(eventSocket);
    this.eventLoopPromise = this.runEventLoop();
    this.eventLoopPromise.catch(() => undefined);
  }

  private async finishTransaction(
    operationCode: number,
    transaction: TransactionHandle,
    actionName: string,
  ): Promise<void> {
    if (!this.channel || this.attachmentHandle == undefined) {
      throw new Error(`A database must be attached before ${actionName}.`);
    }

    const writer = new XdrWriter();
    writer.writeInt32(operationCode);
    writer.writeInt32(transaction.handle);
    await this.channel.write(writer.toBuffer());

    const operation = await this.readOperation();
    if (operation !== op_response) {
      throw new Error(`Unexpected operation ${operation} while executing transaction ${actionName}.`);
    }

    const response = await this.readResponse();
    assertSuccessfulResponse(response.status, `Firebird ${actionName} failed`);
  }

  private async finishStatement(statement: StatementHandle, option: number, actionName: string): Promise<void> {
    if (!this.channel || this.attachmentHandle == undefined) {
      throw new Error(`A database must be attached before ${actionName}.`);
    }

    const writer = new XdrWriter();
    writer.writeInt32(op_free_statement);
    writer.writeInt32(statement.handle);
    writer.writeInt32(option);
    await this.channel.write(writer.toBuffer());

    const operation = await this.readOperation();
    if (operation !== op_response) {
      throw new Error(`Unexpected operation ${operation} while executing ${actionName}.`);
    }

    const response = await this.readResponse();
    assertSuccessfulResponse(response.status, `Firebird ${actionName} failed`);

    if ((option & dsql.drop) !== 0) {
      this.statementMetadata.delete(statement.handle);
      this.exhaustedCursors.delete(statement.handle);
    }
  }

  private async openOrCreateBlob(
    operationCode: number,
    transaction: TransactionHandle,
    blobId: Uint8Array,
    bpb: Uint8Array,
    actionName: string,
  ): Promise<BlobHandle> {
    if (!this.channel || this.attachmentHandle == undefined) {
      throw new Error(`A database must be attached before ${actionName}.`);
    }

    if (blobId.length !== 8) {
      throw new Error('Blob id must contain exactly 8 bytes.');
    }

    const writer = new XdrWriter();
    writer.writeInt32(operationCode);
    writer.writeBuffer(Buffer.from(bpb));
    writer.writeInt32(transaction.handle);
    writer.writeBytes(Buffer.from(blobId));
    await this.channel.write(writer.toBuffer());

    const operation = await this.readOperation();
    if (operation !== op_response) {
      throw new Error(`Unexpected operation ${operation} while executing ${actionName}.`);
    }

    const response = await this.readResponse();
    assertSuccessfulResponse(response.status, `Firebird ${actionName} failed`);
    return {
      handle: response.handle,
      id: Buffer.from(response.quad),
    };
  }

  private async finishBlob(operationCode: number, blob: BlobHandle, actionName: string): Promise<void> {
    if (!this.channel || this.attachmentHandle == undefined) {
      throw new Error(`A database must be attached before ${actionName}.`);
    }

    const writer = new XdrWriter();
    writer.writeInt32(operationCode);
    writer.writeInt32(blob.handle);
    await this.channel.write(writer.toBuffer());

    const operation = await this.readOperation();
    if (operation !== op_response) {
      throw new Error(`Unexpected operation ${operation} while executing ${actionName}.`);
    }

    const response = await this.readResponse();
    assertSuccessfulResponse(response.status, `Firebird ${actionName} failed`);
  }

  private async executePreparedStatement(
    transaction: TransactionHandle,
    statement: StatementHandle,
    inputMessage: Buffer | undefined,
    withOutput: boolean,
  ): Promise<Buffer | undefined> {
    if (!this.channel || this.attachmentHandle == undefined) {
      throw new Error('A database must be attached before executing a statement.');
    }

    const metadata = this.getStatementMetadata(statement);
    const writer = new XdrWriter();
    writer.writeInt32(withOutput ? op_execute2 : op_execute);
    writer.writeInt32(statement.handle);
    writer.writeInt32(transaction.handle);
    writer.writeBuffer(metadata.inputBlr);
    writer.writeInt32(0);
    writer.writeInt32(metadata.inputColumns.length > 0 ? 1 : 0);

    if (metadata.inputColumns.length > 0) {
      writer.writeBytes(this.buildPackedMessage(metadata.inputColumns, metadata.inputMessageLength, inputMessage));
    }

    if (withOutput) {
      writer.writeBuffer(metadata.outputBlr);
      writer.writeInt32(0);
    }

    writer.writeInt32(0);
    writer.writeInt32(0);
    writer.writeInt32(0);
    await this.channel.write(writer.toBuffer());

    let outputMessage: Buffer | undefined;
    let operation = await this.readOperation();

    if (withOutput && operation === op_sql_response) {
      const messages = (await this.channel.readExactly(4)).readInt32BE(0);

      if (messages > 0) {
        outputMessage = await this.readPackedMessageBuffer(metadata.outputColumns, metadata.outputMessageLength);
      }

      operation = await this.readOperation();
    }

    if (operation !== op_response) {
      throw new Error(`Unexpected operation ${operation} while executing a statement.`);
    }

    const response = await this.readResponse();
    assertSuccessfulResponse(response.status, 'Firebird execute statement failed');

    return outputMessage;
  }

  private async getInfo(operationCode: number, handle: number, items: Buffer, actionName: string): Promise<Buffer> {
    if (!this.channel || this.attachmentHandle == undefined) {
      throw new Error(`A database must be attached before ${actionName}.`);
    }

    const writer = new XdrWriter();
    writer.writeInt32(operationCode);
    writer.writeInt32(handle);
    writer.writeInt32(0);
    writer.writeBuffer(items);
    writer.writeInt32(INFO_BUFFER_LENGTH);
    await this.channel.write(writer.toBuffer());

    const operation = await this.readOperation();
    if (operation !== op_response) {
      throw new Error(`Unexpected operation ${operation} while executing ${actionName}.`);
    }

    const response = await this.readResponse();
    assertSuccessfulResponse(response.status, `Firebird ${actionName} failed`);
    return response.data;
  }

  private async writeConnect(database: string): Promise<void> {
    const systemUserName = this.getSystemUserName();
    const identification = Buffer.concat([
      writeTraditionalClumplet(CNCT_login, Buffer.from(this.options.username, 'utf8')),
      writeTraditionalClumplet(CNCT_plugin_name, Buffer.from(this.currentPluginName, 'utf8')),
      writeTraditionalClumplet(CNCT_plugin_list, Buffer.from(this.buildConnectPluginList(), 'utf8')),
      this.writeMultiPartConnectParameter(CNCT_specific_data, this.currentPlugin!.initialData),
      writeTraditionalClumplet(CNCT_client_crypt, Buffer.from([WIRE_CRYPT_ENABLED])),
      writeTraditionalClumplet(CNCT_user, Buffer.from(systemUserName, 'utf8')),
      writeTraditionalClumplet(CNCT_host, Buffer.from(hostname(), 'utf8')),
      writeTraditionalClumplet(CNCT_user_verification, Buffer.alloc(0)),
    ]);

    const writer = new XdrWriter();
    writer.writeInt32(op_connect);
    writer.writeInt32(0);
    writer.writeInt32(CONNECT_VERSION3);
    writer.writeInt32(arch_generic);
    writer.writeString(database);
    writer.writeInt32(SUPPORTED_PROTOCOLS.length);
    writer.writeBuffer(identification);

    let weight = SUPPORTED_PROTOCOLS.length;

    for (const protocolVersion of SUPPORTED_PROTOCOLS) {
      writer.writeInt32(protocolVersion);
      writer.writeInt32(arch_generic);
      writer.writeInt32(0);
      writer.writeInt32(ptype_batch_send);
      // FIXME: ptype_lazy_send
      writer.writeInt32(weight--);
    }

    await this.channel!.write(writer.toBuffer());
  }

  private async writeAttachmentOperation(operation: number, database: string, dpb: Buffer): Promise<void> {
    const writer = new XdrWriter();
    writer.writeInt32(operation);
    writer.writeInt32(0);
    writer.writeString(database);
    writer.writeBuffer(dpb);
    await this.channel!.write(writer.toBuffer());
  }

  private async performConnectHandshake(database: string): Promise<Buffer | undefined> {
    this.currentPluginName = AUTH_PLUGINS[0];
    this.currentPlugin = createAuthPlugin(this.currentPluginName, this.options.password);
    this.clientAuthListSent = false;
    this.pendingServerKeys.length = 0;

    await this.writeConnect(database);

    while (true) {
      const operation = await this.readOperation();

      if (operation === op_accept) {
        return this.currentPlugin.initialData;
      }

      if (operation === op_accept_data || operation === op_cond_accept) {
        const accept = await this.readAcceptMessage();
        this.recordServerKeys(accept.keys);
        const attachAuthData = accept.authenticated ? undefined : this.processAcceptPlugin(accept);

        if (operation === op_cond_accept && !accept.authenticated) {
          await this.writeContinueAuthentication(attachAuthData ?? Buffer.alloc(0));
          continue;
        }

        if (accept.authenticated) {
          await this.enableWireCryptIfAvailable();
        }

        return attachAuthData;
      }

      if (operation === op_cont_auth) {
        const authData = await this.readContinueAuthenticationMessage();
        this.recordServerKeys(authData.keys);
        const response = this.processAcceptPlugin(authData);
        await this.writeContinueAuthentication(response);
        continue;
      }

      if (operation === op_response) {
        const response = await this.readResponse();
        assertSuccessfulResponse(response.status, 'Firebird connect failed');
        this.recordServerKeys(response.data);
        await this.enableWireCryptIfAvailable();
        return undefined;
      }

      if (operation === op_reject) {
        throw new Error('Firebird server rejected all proposed wire protocols.');
      }

      throw new Error(`Unexpected operation ${operation} during connect handshake.`);
    }
  }

  private async executeAttachmentOperation(
    operation: number,
    database: string,
    baseDpb: Buffer,
    attachAuthData: Buffer | undefined,
    actionName: string,
  ): Promise<AttachmentHandle> {
    const dpb = this.buildAttachmentDpb(baseDpb, attachAuthData);
    await this.writeAttachmentOperation(operation, database, dpb);

    while (true) {
      const responseOperation = await this.readOperation();
      if (responseOperation === op_cont_auth) {
        const authData = await this.readContinueAuthenticationMessage();
        this.recordServerKeys(authData.keys);
        const response = this.processAcceptPlugin(authData);
        await this.writeContinueAuthentication(response);
        continue;
      }

      if (responseOperation === op_response) {
        const response = await this.readResponse();
        assertSuccessfulResponse(response.status, `Firebird ${actionName} failed`);
        this.recordServerKeys(response.data);
        await this.enableWireCryptIfAvailable();
        this.attachmentHandle = response.handle;
        return { handle: response.handle };
      }

      throw new Error(`Unexpected operation ${responseOperation} during ${actionName}.`);
    }
  }

  private processAcceptPlugin(message: AcceptMessage): Buffer {
    if (message.pluginName && message.pluginName !== this.currentPluginName) {
      if (!AUTH_PLUGINS.includes(message.pluginName as AuthPluginName)) {
        throw new Error(`Firebird requested unsupported authentication plugin ${message.pluginName}.`);
      }

      this.currentPluginName = message.pluginName as AuthPluginName;
      this.currentPlugin = createAuthPlugin(this.currentPluginName, this.options.password);
      this.clientAuthListSent = false;
    }

    if (!this.currentPlugin) {
      throw new Error('No authentication plugin is active.');
    }

    if (message.data.length === 0) {
      return this.currentPlugin.initialData;
    }

    return this.currentPlugin.continueAuthentication(
      this.normalizeLogin(this.options.username),
      this.options.password,
      message.data,
    );
  }

  private async writeContinueAuthentication(data: Buffer): Promise<void> {
    const writer = new XdrWriter();
    writer.writeInt32(op_cont_auth);
    writer.writeBuffer(data);
    writer.writeString(this.currentPluginName);
    writer.writeString(this.clientAuthListSent ? '' : this.buildRemainingPluginList(this.currentPluginName));
    writer.writeBuffer(Buffer.alloc(0));
    await this.channel!.write(writer.toBuffer());
    this.clientAuthListSent = true;
  }

  private recordServerKeys(keys: Buffer): void {
    if (keys.length > 0) {
      this.pendingServerKeys.push(Buffer.from(keys));
    }
  }

  private async enableWireCryptIfAvailable(): Promise<void> {
    if (this.wireCryptEnabled || !this.channel || !this.currentPlugin) {
      return;
    }

    const sessionKey = this.currentPlugin.getSessionKey();
    if (!sessionKey || this.pendingServerKeys.length === 0) {
      return;
    }

    const session = createWireCryptSession(this.pendingServerKeys, sessionKey);
    if (!session) {
      return;
    }

    const writer = new XdrWriter();
    writer.writeInt32(op_crypt);
    writer.writeString(session.pluginName);
    writer.writeString(session.keyType);
    await this.channel.write(writer.toBuffer());

    this.channel.setTransforms({
      incoming: (buffer) => session.incoming.transform(buffer),
      outgoing: (buffer) => session.outgoing.transform(buffer),
    });

    const operation = await this.readOperation();
    if (operation !== op_response) {
      throw new Error(`Unexpected operation ${operation} while enabling wire encryption.`);
    }

    const response = await this.readResponse();
    assertSuccessfulResponse(response.status, 'Firebird wire encryption setup failed');
    this.pendingServerKeys.length = 0;
    this.wireCryptEnabled = true;
  }

  private buildRemainingPluginList(currentPluginName: AuthPluginName): string {
    const index = AUTH_PLUGINS.indexOf(currentPluginName);
    return index === -1 ? currentPluginName : AUTH_PLUGINS.slice(index).join(',');
  }

  private concatInfoBuffers(buffers: readonly Buffer[]): Buffer {
    return Buffer.concat(
      buffers
        .filter((buffer) => buffer.length > 0)
        .map((buffer, index) =>
          index + 1 < buffers.length && buffer[buffer.length - 1] === commonInfo.end ? buffer.subarray(0, -1) : buffer,
        ),
    );
  }

  private buildAttachmentDpb(baseDpb: Buffer, attachAuthData: Buffer | undefined): Buffer {
    if (!attachAuthData) {
      return baseDpb;
    }

    const clumplets = this.readDpbClumplets(baseDpb).filter(
      ({ tag }) => tag !== dpb.auth_plugin_name && tag !== dpb.auth_plugin_list && tag !== dpb.specific_auth_data,
    );

    const parts = [Buffer.from([dpb.version2]), ...clumplets.map(({ tag, value }) => writeWideClumplet(tag, value))];

    if (!clumplets.some(({ tag }) => tag === dpb.utf8_filename)) {
      parts.push(writeWideClumplet(dpb.utf8_filename, Buffer.alloc(0)));
    }

    parts.push(writeWideStringClumplet(dpb.auth_plugin_name, this.currentPluginName));
    parts.push(writeWideStringClumplet(dpb.auth_plugin_list, this.buildRemainingPluginList(this.currentPluginName)));
    parts.push(writeWideClumplet(dpb.specific_auth_data, attachAuthData));

    return Buffer.concat(parts);
  }

  private normalizeLogin(login: string): string {
    if (login.length > 2 && login.startsWith('"') && login.endsWith('"')) {
      let normalized = login.slice(1, -1);
      for (let i = 0; i < normalized.length; i++) {
        if (normalized[i] !== '"') {
          continue;
        }

        if (i + 1 < normalized.length && normalized[i + 1] === '"') {
          normalized = normalized.slice(0, i) + normalized.slice(i + 1);
          i++;
          continue;
        }

        normalized = normalized.slice(0, i);
        break;
      }
      return normalized;
    }

    return login.toUpperCase();
  }

  private buildConnectPluginList(): string {
    return AUTH_PLUGINS.join(',');
  }

  private readDpbClumplets(buffer: Buffer): DpbClumplet[] {
    if (buffer.length === 0) {
      throw new Error('DPB must not be empty.');
    }

    const version = buffer[0];
    if (version !== dpb.version1 && version !== dpb.version2) {
      throw new Error(`Unsupported DPB version ${version}.`);
    }

    const clumplets: DpbClumplet[] = [];
    let offset = 1;

    while (offset < buffer.length) {
      const tag = buffer[offset++];
      let valueLength: number;

      if (version === dpb.version1) {
        if (offset >= buffer.length) {
          throw new Error('Invalid DPB: missing traditional clumplet length.');
        }
        valueLength = buffer[offset++];
      } else {
        if (offset + 4 > buffer.length) {
          throw new Error('Invalid DPB: missing wide clumplet length.');
        }
        valueLength = buffer.readUInt32LE(offset);
        offset += 4;
      }

      if (offset + valueLength > buffer.length) {
        throw new Error(`Invalid DPB: clumplet ${tag} overruns the buffer.`);
      }

      clumplets.push({
        tag,
        value: buffer.subarray(offset, offset + valueLength),
      });
      offset += valueLength;
    }

    return clumplets;
  }

  private writeMultiPartConnectParameter(parameterType: number, value: Buffer): Buffer {
    const parts: Buffer[] = [];
    let position = 0;
    let step = 0;

    while (position < value.length) {
      const toWrite = Math.min(value.length - position, 254);
      parts.push(Buffer.from([parameterType, toWrite + 1, step++]));
      parts.push(value.subarray(position, position + toWrite));
      position += toWrite;
    }

    return Buffer.concat(parts);
  }

  private buildEventBlock(names: readonly string[]): Buffer {
    const parts = [Buffer.from([epb.version1])];

    for (const name of names) {
      const encodedName = Buffer.from(name, 'utf8');
      if (encodedName.length > 255) {
        throw new Error(`Invalid event name '${name}'.`);
      }

      parts.push(Buffer.from([encodedName.length]));
      parts.push(encodedName);
      parts.push(Buffer.alloc(4));
    }

    return Buffer.concat(parts);
  }

  private calculateEventCounts(previous: Buffer, current: Buffer, names: readonly string[]): [string, number][] {
    const counters: [string, number][] = [];
    let previousOffset = 1;
    let currentOffset = 1;

    for (const name of names) {
      const previousNameLength = previous[previousOffset++] ?? 0;
      previousOffset += previousNameLength;

      const currentNameLength = current[currentOffset++] ?? 0;
      currentOffset += currentNameLength;

      const previousCount = previous.readUInt32LE(previousOffset);
      previousOffset += 4;

      const currentCount = current.readUInt32LE(currentOffset);
      currentOffset += 4;

      counters.push([name, currentCount - previousCount]);
    }

    return counters;
  }

  private parseAuxiliaryPort(address: Buffer): number {
    if (address.length < 4) {
      throw new Error('Firebird returned an invalid auxiliary event address.');
    }

    return address.readUInt16BE(2);
  }

  private getEventHost(): string {
    if (this.socket?.remoteAddress) {
      return this.socket.remoteAddress.startsWith('::ffff:')
        ? this.socket.remoteAddress.slice('::ffff:'.length)
        : this.socket.remoteAddress;
    }

    return this.options.host;
  }

  private async runEventLoop(): Promise<void> {
    try {
      while (this.eventChannel) {
        const operation = await this.readOperationFrom(this.eventChannel);

        if (operation === op_event) {
          const event = await this.readEventMessage(this.eventChannel);
          await this.dispatchEvent(event);
          continue;
        }

        if (operation === op_disconnect) {
          break;
        }

        throw new Error(`Unexpected operation ${operation} on the Firebird event channel.`);
      }
    } catch (error) {
      if (this.eventChannel) {
        throw error;
      }
    } finally {
      this.eventChannel = undefined;

      if (this.eventSocket) {
        const eventSocket = this.eventSocket;
        this.eventSocket = undefined;
        eventSocket.destroy();
      }
    }
  }

  private async dispatchEvent(event: EventMessage): Promise<void> {
    const subscription = this.eventSubscriptions.get(event.requestId);

    if (!subscription) {
      return;
    }

    const counters = this.calculateEventCounts(subscription.eventBuffer, event.items, subscription.names);
    subscription.eventBuffer = Buffer.from(event.items);

    if (this.eventSubscriptions.get(subscription.id) === subscription) {
      await this.runMainChannelTask(async () => {
        if (this.eventSubscriptions.get(subscription.id) !== subscription) {
          return;
        }

        await this.sendQueueEvents(subscription);
      });
    }

    await subscription.callback(counters);
  }

  private getSystemUserName(): string {
    try {
      return userInfo().username ?? 'node-firebird-driver-wire';
    } catch {
      return 'node-firebird-driver-wire';
    }
  }

  private async readOperation(): Promise<number> {
    return await this.readOperationFrom(this.channel!);
  }

  private async sendQueueEvents(subscription: EventSubscription): Promise<void> {
    const writer = new XdrWriter();
    writer.writeInt32(op_que_events);
    writer.writeInt32(0);
    writer.writeBuffer(subscription.eventBuffer);
    writer.writeInt32(0);
    writer.writeInt32(0);
    writer.writeInt32(subscription.id);
    await this.channel!.write(writer.toBuffer());

    const operation = await this.readOperation();
    if (operation !== op_response) {
      throw new Error(`Unexpected operation ${operation} while queueing events.`);
    }

    const response = await this.readResponse();
    assertSuccessfulResponse(response.status, 'Firebird queue events failed');
  }

  private async readOperationFrom(channel: SocketChannel): Promise<number> {
    while (true) {
      const operationBuffer = await channel.readExactly(4);
      const operation = operationBuffer.readInt32BE(0);
      if (operation !== op_dummy) {
        return operation;
      }
    }
  }

  private async readAcceptMessage(): Promise<AcceptMessage> {
    await this.channel!.readExactly(12);
    const data = await this.readXdrBuffer();
    const pluginName = await this.readXdrString();
    const authenticated = (await this.channel!.readExactly(4)).readInt32BE(0) === 1;
    const keys = await this.readXdrBuffer();
    return { authenticated, pluginName, data, keys };
  }

  private async readContinueAuthenticationMessage(): Promise<AcceptMessage> {
    const data = await this.readXdrBuffer();
    const pluginName = await this.readXdrString();
    await this.readXdrString();
    const keys = await this.readXdrBuffer();
    return { authenticated: false, pluginName, data, keys };
  }

  private async readResponse(): Promise<ResponseMessage> {
    return await this.readResponseFrom(this.channel!);
  }

  private async readEventMessage(channel: SocketChannel): Promise<EventMessage> {
    const database = (await channel.readExactly(4)).readInt32BE(0);
    const items = await this.readXdrBufferFrom(channel);
    await channel.readExactly(4);
    await channel.readExactly(4);
    const requestId = (await channel.readExactly(4)).readInt32BE(0);
    return { database, items, requestId };
  }

  private async readXdrBuffer(): Promise<Buffer> {
    return await this.readXdrBufferFrom(this.channel!);
  }

  private async readXdrBufferFrom(channel: SocketChannel): Promise<Buffer> {
    const length = (await channel.readExactly(4)).readInt32BE(0);
    if (length === 0) {
      return Buffer.alloc(0);
    }
    const padded = await channel.readExactly(length + ((4 - (length % 4)) & 3));
    return padded.subarray(0, length);
  }

  private async readXdrString(): Promise<string> {
    return (await this.readXdrBuffer()).toString('utf8');
  }

  private async readResponseFrom(channel: SocketChannel): Promise<ResponseMessage> {
    const handle = (await channel.readExactly(4)).readInt32BE(0);
    const quad = await channel.readExactly(8);
    const objectId = quad.readBigInt64BE(0);
    const data = await this.readXdrBufferFrom(channel);
    const status = parseStatusVector(await this.readStatusVectorBufferFrom(channel));
    return { handle, objectId, quad, data, status };
  }

  private async readStatusVectorBufferFrom(channel: SocketChannel): Promise<Buffer> {
    const chunks: Buffer[] = [];
    while (true) {
      const tagChunk = await channel.readExactly(4);
      const tag = tagChunk.readInt32BE(0);
      chunks.push(tagChunk);
      if (tag === 0) {
        break;
      }

      const valueChunk = await channel.readExactly(4);
      chunks.push(valueChunk);
      if (tag === 2 || tag === 3 || tag === 5) {
        const length = valueChunk.readInt32BE(0);
        if (length > 0) {
          const paddedLength = length + ((4 - (length % 4)) & 3);
          const valueBuffer = await channel.readExactly(paddedLength);
          chunks.push(valueBuffer.subarray(0, length));
        }
      }
    }
    return Buffer.concat(chunks);
  }

  private parseStatementMetadata(data: Buffer): StatementMetadata {
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
          ({ value: statementType, nextOffset: offset } = this.readInfoNumeric(data, offset));
          break;

        case statementInfo.sqlStmtFlags:
          ({ value: statementFlag, nextOffset: offset } = this.readInfoNumeric(data, offset));
          break;

        case statementInfo.sqlSelect:
          outputSection = true;
          break;

        case statementInfo.sqlBind:
          outputSection = false;
          break;

        case statementInfo.sqlDescribeVars: {
          const describeInfo = this.readInfoNumeric(data, offset);
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
                const sequenceInfo = this.readInfoNumeric(data, offset);
                const sequence = sequenceInfo.value;
                offset = sequenceInfo.nextOffset;
                const targetColumns = outputSection ? outputColumns : inputColumns;

                while (targetColumns.length < sequence) {
                  targetColumns.push({
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
                  });
                }

                currentColumn = targetColumns[sequence - 1];
                break;
              }

              case statementInfo.sqlType: {
                const typeInfo = this.readInfoNumeric(data, offset);
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
                  const info = this.readInfoNumeric(data, offset);
                  currentColumn.subType = info.value;
                  currentColumn.charSet = info.value;
                  offset = info.nextOffset;
                } else {
                  ({ nextOffset: offset } = this.readInfoNumeric(data, offset));
                }
                break;

              case statementInfo.sqlScale:
                if (currentColumn) {
                  const info = this.readInfoNumeric(data, offset);
                  currentColumn.scale = info.value;
                  offset = info.nextOffset;
                } else {
                  ({ nextOffset: offset } = this.readInfoNumeric(data, offset));
                }
                break;

              case statementInfo.sqlLength:
                if (currentColumn) {
                  const info = this.readInfoNumeric(data, offset);
                  currentColumn.length = info.value;
                  offset = info.nextOffset;
                } else {
                  ({ nextOffset: offset } = this.readInfoNumeric(data, offset));
                }
                break;

              case statementInfo.sqlField:
                if (currentColumn) {
                  const info = this.readInfoString(data, offset);
                  currentColumn.field = info.value;
                  offset = info.nextOffset;
                } else {
                  ({ nextOffset: offset } = this.readInfoString(data, offset));
                }
                break;

              case statementInfo.sqlRelation:
                if (currentColumn) {
                  const info = this.readInfoString(data, offset);
                  currentColumn.relation = info.value;
                  offset = info.nextOffset;
                } else {
                  ({ nextOffset: offset } = this.readInfoString(data, offset));
                }
                break;

              case statementInfo.sqlAlias:
                if (currentColumn) {
                  const info = this.readInfoString(data, offset);
                  currentColumn.alias = info.value;
                  offset = info.nextOffset;
                } else {
                  ({ nextOffset: offset } = this.readInfoString(data, offset));
                }
                break;

              default:
                ({ nextOffset: offset } = this.readInfoString(data, offset));
                break;
            }
          }
          break;
        }

        default:
          ({ nextOffset: offset } = this.readInfoString(data, offset));
          break;
      }
    }

    const normalizedInputColumns = this.normalizeColumns(inputColumns);
    const normalizedOutputColumns = this.normalizeColumns(outputColumns);
    const inputFormat = this.buildMessageFormat(normalizedInputColumns);
    const outputFormat = this.buildMessageFormat(normalizedOutputColumns);

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

  private readInfoNumeric(data: Buffer, offset: number): { value: number; nextOffset: number } {
    if (offset + 2 > data.length) {
      return { value: 0, nextOffset: data.length };
    }

    const length = data.readUInt16LE(offset);
    const valueOffset = offset + 2;

    return {
      value: this.readLittleEndianInteger(data, valueOffset, length),
      nextOffset: Math.min(valueOffset + length, data.length),
    };
  }

  private readInfoString(data: Buffer, offset: number): { value: string; nextOffset: number } {
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

  private readLittleEndianInteger(buffer: Buffer, offset: number, length: number): number {
    let value = 0;
    for (let i = 0; i < length; i++) {
      value += buffer[offset + i] << (8 * i);
    }

    if (length > 0 && (buffer[offset + length - 1] & 0x80) !== 0) {
      value -= 2 ** (length * 8);
    }

    return value;
  }

  // FIXME: This should not be here
  private normalizeColumns(columns: readonly MutableStatementColumn[]): StatementColumn[] {
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

  private buildMessageFormat(columns: MutableStatementColumn[]): { blr: Buffer; messageLength: number } {
    let messageLength = 0;
    const fieldCount = columns.length * 2;
    const parts = [blr_version5, blr_begin, blr_message, 0, fieldCount & 0xff, (fieldCount >> 8) & 0xff];

    for (const column of columns) {
      const { blr, alignment, length } = this.describeColumnType(column);
      if (alignment > 1) {
        messageLength = this.align(messageLength, alignment);
      }

      const offset = messageLength;
      messageLength += length;
      const nullOffset = this.align(messageLength, 2);
      messageLength = nullOffset + 2;

      column.offset = offset;
      column.nullOffset = nullOffset;

      parts.push(...blr, blr_short, 0);
    }

    parts.push(blr_end, blr_eoc);
    return { blr: Buffer.from(parts), messageLength };
  }

  private describeColumnType(column: StatementColumn): { blr: number[]; alignment: number; length: number } {
    switch (column.type) {
      case sqlTypes.SQL_TEXT:
        return {
          blr: [blr_text, column.length & 0xff, (column.length >> 8) & 0xff],
          alignment: 1,
          length: column.length,
        };
      case sqlTypes.SQL_VARYING:
        return {
          blr: [blr_varying, column.length & 0xff, (column.length >> 8) & 0xff],
          alignment: 2,
          length: column.length + 2,
        };
      case sqlTypes.SQL_SHORT:
        return { blr: [blr_short, column.scale & 0xff], alignment: 2, length: 2 };
      case sqlTypes.SQL_LONG:
        return { blr: [blr_long, column.scale & 0xff], alignment: 4, length: 4 };
      case sqlTypes.SQL_INT64:
        return { blr: [blr_int64, column.scale & 0xff], alignment: 8, length: 8 };
      case sqlTypes.SQL_DOUBLE:
        return { blr: [blr_double], alignment: 8, length: 8 };
      case sqlTypes.SQL_TIMESTAMP:
        return { blr: [blr_timestamp], alignment: 4, length: 8 };
      case sqlTypes.SQL_TYPE_DATE:
        return { blr: [blr_sql_date], alignment: 4, length: 4 };
      case sqlTypes.SQL_TYPE_TIME:
        return { blr: [blr_sql_time], alignment: 4, length: 4 };
      case sqlTypes.SQL_TIME_TZ_EX:
        return { blr: [blr_ex_time_tz], alignment: 4, length: 8 };
      case sqlTypes.SQL_BOOLEAN:
        return { blr: [blr_bool], alignment: 1, length: 1 };
      case sqlTypes.SQL_BLOB:
        return {
          blr: [blr_blob2, column.subType & 0xff, (column.subType >> 8) & 0xff, 0, 0],
          alignment: 4,
          length: 8,
        };
      case sqlTypes.SQL_TIMESTAMP_TZ_EX:
        return { blr: [blr_ex_timestamp_tz], alignment: 4, length: 12 };
      case sqlTypes.SQL_NULL:
        return { blr: [blr_null], alignment: 1, length: 0 };
      default:
        throw new Error(`Unsupported Firebird column type ${column.type} for cursor fetch.`);
    }
  }

  private async readPackedMessageBuffer(columns: readonly StatementColumn[], messageLength: number): Promise<Buffer> {
    const rowBuffer = Buffer.alloc(messageLength);
    const view = new DataView(rowBuffer.buffer, rowBuffer.byteOffset, rowBuffer.byteLength);
    const flagBytes = Math.ceil(columns.length / 8);
    const nullBitmap = await this.readPaddedOpaque(flagBytes);

    for (let index = 0; index < columns.length; index++) {
      const column = columns[index];
      const isNull = (nullBitmap[index >> 3] & (1 << (index & 7))) !== 0;
      view.setInt16(column.nullOffset, isNull ? -1 : 0, LITTLE_ENDIAN);
      if (isNull) {
        continue;
      }

      switch (column.type) {
        case sqlTypes.SQL_TEXT: {
          const value = await this.readPaddedOpaque(column.length);
          value.copy(rowBuffer, column.offset);
          break;
        }

        case sqlTypes.SQL_VARYING: {
          const valueLength = await this.readXdrInt32();
          const value = await this.readPaddedOpaque(valueLength);
          view.setUint16(column.offset, valueLength, LITTLE_ENDIAN);
          value.copy(rowBuffer, column.offset + 2);
          break;
        }

        case sqlTypes.SQL_TYPE_DATE:
        case sqlTypes.SQL_TYPE_TIME:
          view.setInt32(column.offset, await this.readXdrInt32(), LITTLE_ENDIAN);
          break;

        case sqlTypes.SQL_TIME_TZ_EX:
          view.setInt32(column.offset, await this.readXdrInt32(), LITTLE_ENDIAN);
          view.setUint16(column.offset + 4, this.decodeTimeZoneValue(await this.readXdrInt32()), LITTLE_ENDIAN);
          view.setInt16(column.offset + 6, this.decodeTimeZoneOffset(await this.readXdrInt32()), LITTLE_ENDIAN);
          break;

        case sqlTypes.SQL_DOUBLE: {
          const value = await this.channel!.readExactly(8);
          view.setFloat64(column.offset, value.readDoubleBE(0), LITTLE_ENDIAN);
          break;
        }

        case sqlTypes.SQL_TIMESTAMP:
          view.setInt32(column.offset, await this.readXdrInt32(), LITTLE_ENDIAN);
          view.setInt32(column.offset + 4, await this.readXdrInt32(), LITTLE_ENDIAN);
          break;

        case sqlTypes.SQL_TIMESTAMP_TZ_EX:
          view.setInt32(column.offset, await this.readXdrInt32(), LITTLE_ENDIAN);
          view.setInt32(column.offset + 4, await this.readXdrInt32(), LITTLE_ENDIAN);
          view.setUint16(column.offset + 8, this.decodeTimeZoneValue(await this.readXdrInt32()), LITTLE_ENDIAN);
          view.setInt16(column.offset + 10, await this.readXdrInt32(), LITTLE_ENDIAN);
          break;

        case sqlTypes.SQL_BOOLEAN: {
          const value = await this.readPaddedOpaque(1);
          rowBuffer[column.offset] = value[0] ?? 0;
          break;
        }

        case sqlTypes.SQL_BLOB: {
          const value = await this.channel!.readExactly(8);
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

  private async readPaddedOpaque(length: number): Promise<Buffer> {
    if (length === 0) {
      return Buffer.alloc(0);
    }

    const paddedLength = length + ((4 - (length % 4)) & 3);
    const value = await this.channel!.readExactly(paddedLength);

    return value.subarray(0, length);
  }

  private async readXdrInt32(): Promise<number> {
    return (await this.channel!.readExactly(4)).readInt32BE(0);
  }

  private async readFetchBatchMarker(statementHandle: number): Promise<void> {
    const operation = await this.readOperation();
    if (operation !== op_fetch_response) {
      throw new Error(`Unexpected operation ${operation} while completing a cursor fetch batch.`);
    }

    const status = (await this.channel!.readExactly(4)).readInt32BE(0);
    const messages = (await this.channel!.readExactly(4)).readInt32BE(0);
    if (messages !== 0) {
      throw new Error(`Unexpected trailing fetch batch payload size ${messages}.`);
    }

    if (status === FETCH_NO_DATA) {
      this.exhaustedCursors.add(statementHandle);
      return;
    }

    if (status !== 0) {
      throw new Error(`Firebird cursor fetch batch failed with status ${status}.`);
    }
  }

  private align(value: number, alignment: number): number {
    return alignment > 1 ? (value + alignment - 1) & ~(alignment - 1) : value;
  }

  private decodeTimeZoneValue(encodedValue: number): number {
    return encodedValue & 0xffff;
  }

  private decodeTimeZoneOffset(encodedValue: number): number {
    const value = this.decodeTimeZoneValue(encodedValue);
    return value - 1440;
  }

  private buildPackedMessage(
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
          writer.writeInt32(this.encodeTimeZoneOffset(view.getInt16(column.offset + 6, LITTLE_ENDIAN)));
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

  private encodeTimeZoneOffset(offsetMinutes: number): number {
    return offsetMinutes + 1440;
  }
}
