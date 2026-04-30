import { Buffer } from 'node:buffer';
import { connect as connectSocket, Socket } from 'node:net';
import { endianness, hostname, userInfo } from 'node:os';

import { ClientAuthPlugin, createAuthPlugin } from './auth/plugins';
import {
  arch_generic,
  AUTH_PLUGINS,
  AuthPluginName,
  blr_begin,
  blr_blob2,
  blr_bool,
  blr_double,
  blr_end,
  blr_eoc,
  blr_int64,
  blr_long,
  blr_message,
  blr_short,
  blr_sql_date,
  blr_sql_time,
  blr_text,
  blr_timestamp,
  blr_varying,
  blr_version5,
  CNCT_client_crypt,
  CNCT_host,
  CNCT_login,
  CNCT_plugin_list,
  CNCT_plugin_name,
  CNCT_specific_data,
  CNCT_user,
  CNCT_user_verification,
  CONNECT_VERSION3,
  DSQL_drop,
  isc_dpb_auth_plugin_list,
  isc_dpb_auth_plugin_name,
  isc_dpb_specific_auth_data,
  isc_dpb_utf8_filename,
  isc_dpb_version1,
  isc_dpb_version2,
  isc_info_end,
  isc_info_sql_alias,
  isc_info_sql_bind,
  isc_info_sql_describe_end,
  isc_info_sql_describe_vars,
  isc_info_sql_field,
  isc_info_sql_length,
  isc_info_sql_owner,
  isc_info_sql_relation,
  isc_info_sql_relation_alias,
  isc_info_sql_scale,
  isc_info_sql_select,
  isc_info_sql_sqlda_seq,
  isc_info_sql_stmt_select,
  isc_info_sql_stmt_select_for_upd,
  isc_info_sql_stmt_type,
  isc_info_sql_sub_type,
  isc_info_sql_type,
  isc_info_truncated,
  op_accept,
  op_accept_data,
  op_allocate_statement,
  op_attach,
  op_cancel_blob,
  op_commit,
  op_commit_retaining,
  op_cond_accept,
  op_connect,
  op_create_blob2,
  op_cont_auth,
  op_create,
  op_detach,
  op_disconnect,
  op_drop_database,
  op_dummy,
  op_execute,
  op_fetch,
  op_fetch_response,
  op_free_statement,
  op_get_segment,
  op_close_blob,
  op_open_blob2,
  op_ping,
  op_put_segment,
  op_prepare_statement,
  op_reject,
  op_response,
  op_rollback,
  op_rollback_retaining,
  op_seek_blob,
  op_transaction,
  ptype_batch_send,
  SQL_BLOB,
  SQL_BOOLEAN,
  SQL_DOUBLE,
  SQL_INT64,
  SQL_LONG,
  SQL_SHORT,
  SQL_TEXT,
  SQL_TIMESTAMP,
  SQL_TYPE_DATE,
  SQL_TYPE_TIME,
  SQL_VARYING,
  SUPPORTED_PROTOCOLS,
  WIRE_CRYPT_ENABLED,
} from './constants';
import { SocketChannel } from './socket-channel';
import { assertSuccessfulResponse, parseStatusVector } from './status';
import { writeTraditionalClumplet, writeWideClumplet, writeWideStringClumplet, XdrWriter } from './xdr';

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
  readonly subType: number;
  readonly scale: number;
  readonly length: number;
  readonly nullable: boolean;
}

export interface CursorHandle {
  readonly statement: StatementHandle;
  readonly columns: readonly StatementColumn[];
  readonly fetchBlr: Buffer;
  readonly fetchMessageLength: number;
}

interface AcceptMessage {
  readonly authenticated: boolean;
  readonly pluginName: string;
  readonly data: Buffer;
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
  readonly columns: readonly StatementColumn[];
  readonly fetchBlr: Buffer;
  readonly fetchMessageLength: number;
}

interface MutableStatementColumn {
  alias: string;
  field: string;
  relation: string;
  type: number;
  subType: number;
  scale: number;
  length: number;
  nullable: boolean;
}

interface FetchLayoutColumn {
  readonly type: number;
  readonly length: number;
  readonly scale: number;
  readonly offset: number;
  readonly nullOffset: number;
}

const LITTLE_ENDIAN = endianness() === 'LE';
const FETCH_NO_DATA = 100;

const PREPARE_STATEMENT_INFO_ITEMS = Buffer.from([
  isc_info_sql_stmt_type,
  isc_info_sql_select,
  isc_info_sql_describe_vars,
  isc_info_sql_sqlda_seq,
  isc_info_sql_type,
  isc_info_sql_sub_type,
  isc_info_sql_scale,
  isc_info_sql_length,
  isc_info_sql_field,
  isc_info_sql_alias,
  isc_info_sql_relation,
  isc_info_sql_relation_alias,
  isc_info_sql_owner,
  isc_info_sql_describe_end,
  isc_info_sql_bind,
  isc_info_sql_describe_vars,
  isc_info_sql_sqlda_seq,
  isc_info_sql_type,
  isc_info_sql_sub_type,
  isc_info_sql_scale,
  isc_info_sql_length,
  isc_info_sql_describe_end,
]);
const PREPARE_STATEMENT_INFO_BUFFER_LENGTH = 32767;

export class WireProtocol {
  private socket?: Socket;
  private channel?: SocketChannel;
  private attachmentHandle?: number;
  private currentPluginName: AuthPluginName = 'Legacy_Auth';
  private currentPlugin?: ClientAuthPlugin;
  private clientAuthListSent = false;
  private readonly statementMetadata = new Map<number, StatementMetadata>();
  private readonly exhaustedCursors = new Set<number>();

  constructor(private readonly options: WireProtocolOptions) {}

  async attach(database: string, dpb: Buffer): Promise<AttachmentHandle> {
    if (this.attachmentHandle) {
      throw new Error('A database is already attached on this protocol instance.');
    }

    await this.openSocket();
    const attachAuthData = await this.performConnectHandshake(database);
    return await this.executeAttachmentOperation(op_attach, database, dpb, attachAuthData, 'attach');
  }

  async createDatabase(database: string, dpb: Buffer): Promise<AttachmentHandle> {
    if (this.attachmentHandle) {
      throw new Error('A database is already attached on this protocol instance.');
    }

    await this.openSocket();
    const attachAuthData = await this.performConnectHandshake(database);
    return await this.executeAttachmentOperation(op_create, database, dpb, attachAuthData, 'create');
  }

  async detach(attachment: AttachmentHandle): Promise<void> {
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
  }

  async dropDatabase(attachment: AttachmentHandle): Promise<void> {
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
  }

  async ping(): Promise<void> {
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
  }

  async startTransaction(tpb: Buffer): Promise<TransactionHandle> {
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
  }

  async commit(transaction: TransactionHandle): Promise<void> {
    await this.finishTransaction(op_commit, transaction, 'commit');
  }

  async rollback(transaction: TransactionHandle): Promise<void> {
    await this.finishTransaction(op_rollback, transaction, 'rollback');
  }

  async commitRetaining(transaction: TransactionHandle): Promise<void> {
    await this.finishTransaction(op_commit_retaining, transaction, 'commit retaining');
  }

  async rollbackRetaining(transaction: TransactionHandle): Promise<void> {
    await this.finishTransaction(op_rollback_retaining, transaction, 'rollback retaining');
  }

  async createBlob(transaction: TransactionHandle, bpb: Uint8Array = Buffer.alloc(0)): Promise<BlobHandle> {
    return await this.openOrCreateBlob(op_create_blob2, transaction, Buffer.alloc(8), bpb, 'create blob');
  }

  async openBlob(
    transaction: TransactionHandle,
    blobId: Uint8Array,
    bpb: Uint8Array = Buffer.alloc(0),
  ): Promise<BlobHandle> {
    return await this.openOrCreateBlob(op_open_blob2, transaction, blobId, bpb, 'open blob');
  }

  async getSegment(blob: BlobHandle, bufferLength: number): Promise<BlobSegmentResponse> {
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
  }

  async putSegment(blob: BlobHandle, segment: Buffer): Promise<void> {
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
  }

  async seekBlob(blob: BlobHandle, mode: number, offset: number): Promise<number> {
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
    return response.quad.readInt32BE(4);
  }

  async closeBlob(blob: BlobHandle): Promise<void> {
    await this.finishBlob(op_close_blob, blob, 'close blob');
  }

  async cancelBlob(blob: BlobHandle): Promise<void> {
    await this.finishBlob(op_cancel_blob, blob, 'cancel blob');
  }

  async allocateStatement(): Promise<StatementHandle> {
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
  }

  async prepareStatement(
    transaction: TransactionHandle,
    statement: StatementHandle,
    sql: string,
    sqlDialect = 3,
  ): Promise<void> {
    if (!this.channel || this.attachmentHandle == undefined) {
      throw new Error('A database must be attached before preparing a statement.');
    }

    const writer = new XdrWriter();
    writer.writeInt32(op_prepare_statement);
    writer.writeInt32(transaction.handle);
    writer.writeInt32(statement.handle);
    writer.writeInt32(sqlDialect);
    writer.writeString(sql);
    writer.writeBuffer(PREPARE_STATEMENT_INFO_ITEMS);
    writer.writeInt32(PREPARE_STATEMENT_INFO_BUFFER_LENGTH);
    await this.channel.write(writer.toBuffer());

    const operation = await this.readOperation();
    if (operation !== op_response) {
      throw new Error(`Unexpected operation ${operation} while preparing a statement.`);
    }

    const response = await this.readResponse();
    assertSuccessfulResponse(response.status, 'Firebird prepare statement failed');
    this.statementMetadata.set(statement.handle, this.parseStatementMetadata(response.data));
  }

  async executeStatement(transaction: TransactionHandle, statement: StatementHandle): Promise<void> {
    if (!this.channel || this.attachmentHandle == undefined) {
      throw new Error('A database must be attached before executing a statement.');
    }

    const writer = new XdrWriter();
    writer.writeInt32(op_execute);
    writer.writeInt32(statement.handle);
    writer.writeInt32(transaction.handle);
    writer.writeBuffer(Buffer.alloc(0));
    writer.writeInt32(0);
    writer.writeInt32(0);
    writer.writeInt32(0);
    writer.writeInt32(0);
    writer.writeInt32(0);
    await this.channel.write(writer.toBuffer());

    const operation = await this.readOperation();
    if (operation !== op_response) {
      throw new Error(`Unexpected operation ${operation} while executing a statement.`);
    }

    const response = await this.readResponse();
    assertSuccessfulResponse(response.status, 'Firebird execute statement failed');
  }

  async openCursor(transaction: TransactionHandle, statement: StatementHandle): Promise<CursorHandle> {
    const metadata = this.statementMetadata.get(statement.handle);
    if (!metadata) {
      throw new Error('Statement metadata is not available. Prepare the statement before opening a cursor.');
    }

    if (metadata.type !== isc_info_sql_stmt_select && metadata.type !== isc_info_sql_stmt_select_for_upd) {
      throw new Error('Statement does not produce a selectable cursor.');
    }

    await this.executeStatement(transaction, statement);
    this.exhaustedCursors.delete(statement.handle);
    return {
      statement,
      columns: metadata.columns,
      fetchBlr: metadata.fetchBlr,
      fetchMessageLength: metadata.fetchMessageLength,
    };
  }

  async fetchNext(cursor: CursorHandle): Promise<Buffer | undefined> {
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

    const rowBuffer = await this.readFetchRowBuffer(metadata);
    await this.readFetchBatchMarker(cursor.statement.handle);
    return rowBuffer;
  }

  async freeStatement(statement: StatementHandle): Promise<void> {
    if (!this.channel || this.attachmentHandle == undefined) {
      throw new Error('A database must be attached before freeing a statement.');
    }

    const writer = new XdrWriter();
    writer.writeInt32(op_free_statement);
    writer.writeInt32(statement.handle);
    writer.writeInt32(DSQL_drop);
    await this.channel.write(writer.toBuffer());

    const operation = await this.readOperation();
    if (operation !== op_response) {
      throw new Error(`Unexpected operation ${operation} while freeing a statement.`);
    }

    const response = await this.readResponse();
    assertSuccessfulResponse(response.status, 'Firebird free statement failed');
    this.statementMetadata.delete(statement.handle);
    this.exhaustedCursors.delete(statement.handle);
  }

  async close(): Promise<void> {
    if (this.channel) {
      const writer = new XdrWriter();
      writer.writeInt32(op_disconnect);
      await this.channel.write(writer.toBuffer()).catch(() => undefined);
    }

    if (this.socket) {
      await new Promise<void>((resolve) => {
        this.socket!.once('close', () => resolve());
        this.socket!.end();
      }).catch(() => undefined);
    }

    this.channel = undefined;
    this.socket = undefined;
    this.attachmentHandle = undefined;
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

    await this.writeConnect(database);

    while (true) {
      const operation = await this.readOperation();
      if (operation === op_accept) {
        return this.currentPlugin.initialData;
      }

      if (operation === op_accept_data || operation === op_cond_accept) {
        const accept = await this.readAcceptMessage();
        const attachAuthData = accept.authenticated ? undefined : this.processAcceptPlugin(accept);
        if (operation === op_cond_accept && !accept.authenticated) {
          await this.writeContinueAuthentication(attachAuthData ?? Buffer.alloc(0));
          continue;
        }
        return attachAuthData;
      }

      if (operation === op_cont_auth) {
        const authData = await this.readContinueAuthenticationMessage();
        const response = this.processAcceptPlugin(authData);
        await this.writeContinueAuthentication(response);
        continue;
      }

      if (operation === op_response) {
        const response = await this.readResponse();
        assertSuccessfulResponse(response.status, 'Firebird connect failed');
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
        const response = this.processAcceptPlugin(authData);
        await this.writeContinueAuthentication(response);
        continue;
      }

      if (responseOperation === op_response) {
        const response = await this.readResponse();
        assertSuccessfulResponse(response.status, `Firebird ${actionName} failed`);
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

  private buildRemainingPluginList(currentPluginName: AuthPluginName): string {
    const index = AUTH_PLUGINS.indexOf(currentPluginName);
    return index === -1 ? currentPluginName : AUTH_PLUGINS.slice(index).join(',');
  }

  private buildAttachmentDpb(baseDpb: Buffer, attachAuthData: Buffer | undefined): Buffer {
    if (!attachAuthData) {
      return baseDpb;
    }

    const clumplets = this.readDpbClumplets(baseDpb).filter(
      ({ tag }) =>
        tag !== isc_dpb_auth_plugin_name && tag !== isc_dpb_auth_plugin_list && tag !== isc_dpb_specific_auth_data,
    );

    const parts = [
      Buffer.from([isc_dpb_version2]),
      ...clumplets.map(({ tag, value }) => writeWideClumplet(tag, value)),
    ];

    if (!clumplets.some(({ tag }) => tag === isc_dpb_utf8_filename)) {
      parts.push(writeWideClumplet(isc_dpb_utf8_filename, Buffer.alloc(0)));
    }

    parts.push(writeWideStringClumplet(isc_dpb_auth_plugin_name, this.currentPluginName));
    parts.push(
      writeWideStringClumplet(isc_dpb_auth_plugin_list, this.buildRemainingPluginList(this.currentPluginName)),
    );
    parts.push(writeWideClumplet(isc_dpb_specific_auth_data, attachAuthData));
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

  private readDpbClumplets(dpb: Buffer): DpbClumplet[] {
    if (dpb.length === 0) {
      throw new Error('DPB must not be empty.');
    }

    const version = dpb[0];
    if (version !== isc_dpb_version1 && version !== isc_dpb_version2) {
      throw new Error(`Unsupported DPB version ${version}.`);
    }

    const clumplets: DpbClumplet[] = [];
    let offset = 1;

    while (offset < dpb.length) {
      const tag = dpb[offset++];
      let valueLength: number;

      if (version === isc_dpb_version1) {
        if (offset >= dpb.length) {
          throw new Error('Invalid DPB: missing traditional clumplet length.');
        }
        valueLength = dpb[offset++];
      } else {
        if (offset + 4 > dpb.length) {
          throw new Error('Invalid DPB: missing wide clumplet length.');
        }
        valueLength = dpb.readUInt32LE(offset);
        offset += 4;
      }

      if (offset + valueLength > dpb.length) {
        throw new Error(`Invalid DPB: clumplet ${tag} overruns the buffer.`);
      }

      clumplets.push({
        tag,
        value: dpb.subarray(offset, offset + valueLength),
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

  private getSystemUserName(): string {
    try {
      return userInfo().username || 'node-firebird-driver-wire';
    } catch {
      return 'node-firebird-driver-wire';
    }
  }

  private async readOperation(): Promise<number> {
    while (true) {
      const operationBuffer = await this.channel!.readExactly(4);
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
    await this.readXdrBuffer();
    return { authenticated, pluginName, data };
  }

  private async readContinueAuthenticationMessage(): Promise<AcceptMessage> {
    const data = await this.readXdrBuffer();
    const pluginName = await this.readXdrString();
    await this.readXdrString();
    await this.readXdrBuffer();
    return { authenticated: false, pluginName, data };
  }

  private async readResponse(): Promise<ResponseMessage> {
    const handle = (await this.channel!.readExactly(4)).readInt32BE(0);
    const quad = await this.channel!.readExactly(8);
    const objectId = quad.readBigInt64BE(0);
    const data = await this.readXdrBuffer();
    const status = parseStatusVector(await this.readStatusVectorBuffer());
    return { handle, objectId, quad, data, status };
  }

  private async readXdrBuffer(): Promise<Buffer> {
    const length = (await this.channel!.readExactly(4)).readInt32BE(0);
    if (length === 0) {
      return Buffer.alloc(0);
    }
    const padded = await this.channel!.readExactly(length + ((4 - (length % 4)) & 3));
    return padded.subarray(0, length);
  }

  private async readXdrString(): Promise<string> {
    return (await this.readXdrBuffer()).toString('utf8');
  }

  private async readStatusVectorBuffer(): Promise<Buffer> {
    const chunks: Buffer[] = [];
    while (true) {
      const tagChunk = await this.channel!.readExactly(4);
      const tag = tagChunk.readInt32BE(0);
      chunks.push(tagChunk);
      if (tag === 0) {
        break;
      }

      const valueChunk = await this.channel!.readExactly(4);
      chunks.push(valueChunk);
      if (tag === 2 || tag === 3 || tag === 5) {
        const length = valueChunk.readInt32BE(0);
        if (length > 0) {
          const paddedLength = length + ((4 - (length % 4)) & 3);
          const valueBuffer = await this.channel!.readExactly(paddedLength);
          chunks.push(valueBuffer.subarray(0, length));
        }
      }
    }
    return Buffer.concat(chunks);
  }

  private parseStatementMetadata(data: Buffer): StatementMetadata {
    const columns: MutableStatementColumn[] = [];
    let statementType = 0;
    let outputSection = false;
    let offset = 0;

    while (offset < data.length) {
      const item = data[offset++];
      if (item === isc_info_end) {
        break;
      }

      switch (item) {
        case isc_info_sql_stmt_type:
          ({ value: statementType, nextOffset: offset } = this.readInfoNumeric(data, offset));
          break;

        case isc_info_sql_select:
          outputSection = true;
          break;

        case isc_info_sql_bind:
          outputSection = false;
          break;

        case isc_info_sql_describe_vars: {
          ({ nextOffset: offset } = this.readInfoNumeric(data, offset));

          let currentColumn: MutableStatementColumn | undefined;
          while (offset < data.length) {
            const describeItem = data[offset++];
            if (describeItem === isc_info_sql_describe_end) {
              break;
            }

            if (describeItem === isc_info_end || describeItem === isc_info_truncated) {
              offset--;
              break;
            }

            switch (describeItem) {
              case isc_info_sql_sqlda_seq: {
                const sequenceInfo = this.readInfoNumeric(data, offset);
                const sequence = sequenceInfo.value;
                offset = sequenceInfo.nextOffset;
                if (!outputSection) {
                  break;
                }

                while (columns.length < sequence) {
                  columns.push({
                    alias: '',
                    field: '',
                    relation: '',
                    type: 0,
                    subType: 0,
                    scale: 0,
                    length: 0,
                    nullable: false,
                  });
                }

                currentColumn = columns[sequence - 1];
                break;
              }

              case isc_info_sql_type: {
                const typeInfo = this.readInfoNumeric(data, offset);
                const type = typeInfo.value;
                offset = typeInfo.nextOffset;
                if (currentColumn) {
                  currentColumn.type = type & ~1;
                  currentColumn.nullable = (type & 1) !== 0;
                }
                break;
              }

              case isc_info_sql_sub_type:
                if (currentColumn) {
                  const info = this.readInfoNumeric(data, offset);
                  currentColumn.subType = info.value;
                  offset = info.nextOffset;
                } else {
                  ({ nextOffset: offset } = this.readInfoNumeric(data, offset));
                }
                break;

              case isc_info_sql_scale:
                if (currentColumn) {
                  const info = this.readInfoNumeric(data, offset);
                  currentColumn.scale = info.value;
                  offset = info.nextOffset;
                } else {
                  ({ nextOffset: offset } = this.readInfoNumeric(data, offset));
                }
                break;

              case isc_info_sql_length:
                if (currentColumn) {
                  const info = this.readInfoNumeric(data, offset);
                  currentColumn.length = info.value;
                  offset = info.nextOffset;
                } else {
                  ({ nextOffset: offset } = this.readInfoNumeric(data, offset));
                }
                break;

              case isc_info_sql_field:
                if (currentColumn) {
                  const info = this.readInfoString(data, offset);
                  currentColumn.field = info.value;
                  offset = info.nextOffset;
                } else {
                  ({ nextOffset: offset } = this.readInfoString(data, offset));
                }
                break;

              case isc_info_sql_relation:
                if (currentColumn) {
                  const info = this.readInfoString(data, offset);
                  currentColumn.relation = info.value;
                  offset = info.nextOffset;
                } else {
                  ({ nextOffset: offset } = this.readInfoString(data, offset));
                }
                break;

              case isc_info_sql_alias:
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

    const fetchFormat = this.buildFetchFormat(columns);
    return {
      type: statementType,
      columns,
      fetchBlr: fetchFormat.blr,
      fetchMessageLength: fetchFormat.messageLength,
    };
  }

  private readInfoNumeric(data: Buffer, offset: number): { value: number; nextOffset: number } {
    const length = data.readUInt16LE(offset);
    const valueOffset = offset + 2;
    return {
      value: this.readLittleEndianInteger(data, valueOffset, length),
      nextOffset: valueOffset + length,
    };
  }

  private readInfoString(data: Buffer, offset: number): { value: string; nextOffset: number } {
    const length = data.readUInt16LE(offset);
    const valueOffset = offset + 2;
    return {
      value: data.subarray(valueOffset, valueOffset + length).toString('utf8'),
      nextOffset: valueOffset + length,
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

  private buildFetchFormat(columns: readonly StatementColumn[]): { blr: Buffer; messageLength: number } {
    let messageLength = 0;
    const fieldCount = columns.length * 2;
    const parts = [blr_version5, blr_begin, blr_message, 0, fieldCount & 0xff, (fieldCount >> 8) & 0xff];

    for (const column of columns) {
      const { blr, alignment, length } = this.describeColumnType(column);
      if (alignment > 1) {
        messageLength = this.align(messageLength, alignment);
      }

      messageLength += length;
      messageLength = this.align(messageLength, 2) + 2;

      parts.push(...blr, blr_short, 0);
    }

    parts.push(blr_end, blr_eoc);
    return { blr: Buffer.from(parts), messageLength };
  }

  private describeColumnType(column: StatementColumn): { blr: number[]; alignment: number; length: number } {
    switch (column.type) {
      case SQL_TEXT:
        return {
          blr: [blr_text, column.length & 0xff, (column.length >> 8) & 0xff],
          alignment: 1,
          length: column.length,
        };
      case SQL_VARYING:
        return {
          blr: [blr_varying, column.length & 0xff, (column.length >> 8) & 0xff],
          alignment: 2,
          length: column.length + 2,
        };
      case SQL_SHORT:
        return { blr: [blr_short, column.scale & 0xff], alignment: 2, length: 2 };
      case SQL_LONG:
        return { blr: [blr_long, column.scale & 0xff], alignment: 4, length: 4 };
      case SQL_INT64:
        return { blr: [blr_int64, column.scale & 0xff], alignment: 8, length: 8 };
      case SQL_DOUBLE:
        return { blr: [blr_double], alignment: 8, length: 8 };
      case SQL_TIMESTAMP:
        return { blr: [blr_timestamp], alignment: 4, length: 8 };
      case SQL_TYPE_DATE:
        return { blr: [blr_sql_date], alignment: 4, length: 4 };
      case SQL_TYPE_TIME:
        return { blr: [blr_sql_time], alignment: 4, length: 4 };
      case SQL_BOOLEAN:
        return { blr: [blr_bool], alignment: 1, length: 1 };
      case SQL_BLOB:
        return { blr: [blr_blob2, column.subType & 0xff, (column.subType >> 8) & 0xff, 0, 0], alignment: 4, length: 8 };
      default:
        throw new Error(`Unsupported Firebird column type ${column.type} for cursor fetch.`);
    }
  }

  private async readFetchRowBuffer(metadata: StatementMetadata): Promise<Buffer> {
    const layout = this.buildFetchLayout(metadata.columns);
    const rowBuffer = Buffer.alloc(metadata.fetchMessageLength);
    const view = new DataView(rowBuffer.buffer, rowBuffer.byteOffset, rowBuffer.byteLength);
    const flagBytes = Math.ceil(layout.length / 8);
    const nullBitmap = await this.readPaddedOpaque(flagBytes);

    for (let index = 0; index < layout.length; index++) {
      const column = layout[index];
      const isNull = (nullBitmap[index >> 3] & (1 << (index & 7))) !== 0;
      view.setInt16(column.nullOffset, isNull ? -1 : 0, LITTLE_ENDIAN);
      if (isNull) {
        continue;
      }

      switch (column.type) {
        case SQL_TEXT: {
          const value = await this.readPaddedOpaque(column.length);
          value.copy(rowBuffer, column.offset);
          break;
        }

        case SQL_VARYING: {
          const valueLength = await this.readXdrInt32();
          const value = await this.readPaddedOpaque(valueLength);
          view.setUint16(column.offset, valueLength, LITTLE_ENDIAN);
          value.copy(rowBuffer, column.offset + 2);
          break;
        }

        case SQL_SHORT:
          view.setInt16(column.offset, await this.readXdrInt32(), LITTLE_ENDIAN);
          break;

        case SQL_LONG:
        case SQL_TYPE_DATE:
        case SQL_TYPE_TIME:
          view.setInt32(column.offset, await this.readXdrInt32(), LITTLE_ENDIAN);
          break;

        case SQL_INT64:
          view.setBigInt64(column.offset, await this.readXdrInt64(), LITTLE_ENDIAN);
          break;

        case SQL_DOUBLE: {
          const value = await this.channel!.readExactly(8);
          view.setFloat64(column.offset, value.readDoubleBE(0), LITTLE_ENDIAN);
          break;
        }

        case SQL_TIMESTAMP:
          view.setInt32(column.offset, await this.readXdrInt32(), LITTLE_ENDIAN);
          view.setInt32(column.offset + 4, await this.readXdrInt32(), LITTLE_ENDIAN);
          break;

        case SQL_BOOLEAN: {
          const value = await this.readPaddedOpaque(1);
          rowBuffer[column.offset] = value[0] ?? 0;
          break;
        }

        case SQL_BLOB: {
          view.setInt32(column.offset, await this.readXdrInt32(), LITTLE_ENDIAN);
          view.setInt32(column.offset + 4, await this.readXdrInt32(), LITTLE_ENDIAN);
          break;
        }

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

  private async readXdrInt64(): Promise<bigint> {
    return (await this.channel!.readExactly(8)).readBigInt64BE(0);
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

  private buildFetchLayout(columns: readonly StatementColumn[]): FetchLayoutColumn[] {
    const layout: FetchLayoutColumn[] = [];
    let messageLength = 0;

    for (const column of columns) {
      const { alignment, length } = this.describeColumnType(column);
      if (alignment > 1) {
        messageLength = this.align(messageLength, alignment);
      }

      const offset = messageLength;
      messageLength += length;
      const nullOffset = this.align(messageLength, 2);
      messageLength = nullOffset + 2;

      layout.push({
        type: column.type,
        length: column.length,
        scale: column.scale,
        offset,
        nullOffset,
      });
    }

    return layout;
  }

  private align(value: number, alignment: number): number {
    return alignment > 1 ? (value + alignment - 1) & ~(alignment - 1) : value;
  }
}
