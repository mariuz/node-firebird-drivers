import { Buffer } from 'node:buffer';
import { Socket, connect as connectSocket } from 'node:net';
import { hostname, userInfo } from 'node:os';

import {
  arch_generic,
  AUTH_PLUGINS,
  AuthPluginName,
  CNCT_client_crypt,
  CNCT_host,
  CNCT_login,
  CNCT_plugin_list,
  CNCT_plugin_name,
  CNCT_specific_data,
  CNCT_user,
  CNCT_user_verification,
  CONNECT_VERSION3,
  isc_dpb_auth_plugin_list,
  isc_dpb_auth_plugin_name,
  isc_dpb_lc_ctype,
  isc_dpb_overwrite,
  isc_dpb_page_size,
  isc_dpb_specific_auth_data,
  isc_dpb_sql_dialect,
  isc_dpb_user_name,
  isc_dpb_utf8_filename,
  isc_dpb_version1,
  isc_dpb_version2,
  op_accept,
  op_accept_data,
  op_attach,
  op_cond_accept,
  op_connect,
  op_cont_auth,
  op_create,
  op_detach,
  op_disconnect,
  op_drop_database,
  op_dummy,
  op_ping,
  op_reject,
  op_response,
  ptype_batch_send,
  ptype_lazy_send,
  SUPPORTED_PROTOCOLS,
  WIRE_CRYPT_ENABLED,
} from './constants';
import { createAuthPlugin, ClientAuthPlugin } from './auth/plugins';
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

export interface CreateDatabaseOptions {
  readonly pageSize?: number;
  readonly overwrite?: boolean;
}

interface AcceptMessage {
  readonly authenticated: boolean;
  readonly pluginName: string;
  readonly data: Buffer;
}

interface ResponseMessage {
  readonly handle: number;
  readonly objectId: bigint;
  readonly data: Buffer;
  readonly status: ReturnType<typeof parseStatusVector>;
}

export class WireProtocol {
  private socket?: Socket;
  private channel?: SocketChannel;
  private attachmentHandle?: number;
  private currentPluginName: AuthPluginName = 'Legacy_Auth';
  private currentPlugin?: ClientAuthPlugin;
  private clientAuthListSent = false;

  constructor(private readonly options: WireProtocolOptions) {}

  async attach(database: string): Promise<AttachmentHandle> {
    if (this.attachmentHandle) {
      throw new Error('A database is already attached on this protocol instance.');
    }

    await this.openSocket();
    const attachAuthData = await this.performConnectHandshake(database);
    return await this.executeAttachmentOperation(op_attach, database, this.buildAttachDpb(), attachAuthData, 'attach');
  }

  async createDatabase(database: string, options?: CreateDatabaseOptions): Promise<AttachmentHandle> {
    if (this.attachmentHandle) {
      throw new Error('A database is already attached on this protocol instance.');
    }

    await this.openSocket();
    const attachAuthData = await this.performConnectHandshake(database);
    return await this.executeAttachmentOperation(
      op_create,
      database,
      this.buildCreateDatabaseDpb(options),
      attachAuthData,
      'create',
      options,
    );
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
      writer.writeInt32(ptype_batch_send);
      writer.writeInt32(ptype_lazy_send);
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

  private buildAttachDpb(): Buffer {
    return Buffer.concat([
      Buffer.from([isc_dpb_version1]),
      writeTraditionalClumplet(isc_dpb_user_name, Buffer.from(this.options.username, 'utf8')),
      writeTraditionalClumplet(isc_dpb_lc_ctype, Buffer.from('UTF8', 'ascii')),
      writeTraditionalClumplet(isc_dpb_utf8_filename, Buffer.alloc(0)),
    ]);
  }

  private buildWideAttachDpb(attachAuthData: Buffer): Buffer {
    return Buffer.concat([
      Buffer.from([isc_dpb_version2]),
      writeWideStringClumplet(isc_dpb_user_name, this.options.username),
      writeWideStringClumplet(isc_dpb_lc_ctype, 'UTF8'),
      writeWideClumplet(isc_dpb_utf8_filename, Buffer.alloc(0)),
      writeWideStringClumplet(isc_dpb_auth_plugin_name, this.currentPluginName),
      writeWideStringClumplet(isc_dpb_auth_plugin_list, this.buildRemainingPluginList(this.currentPluginName)),
      writeWideClumplet(isc_dpb_specific_auth_data, attachAuthData),
    ]);
  }

  private buildWideCreateDatabaseDpb(attachAuthData: Buffer, options?: CreateDatabaseOptions): Buffer {
    const pageSize = Buffer.alloc(4);
    pageSize.writeUInt32LE(options?.pageSize ?? 4096, 0);

    return Buffer.concat([
      Buffer.from([isc_dpb_version2]),
      writeWideStringClumplet(isc_dpb_user_name, this.options.username),
      writeWideStringClumplet(isc_dpb_lc_ctype, 'UTF8'),
      writeWideClumplet(isc_dpb_sql_dialect, Buffer.from([3])),
      writeWideClumplet(isc_dpb_page_size, pageSize),
      writeWideClumplet(isc_dpb_overwrite, Buffer.from([options?.overwrite ? 1 : 0])),
      writeWideClumplet(isc_dpb_utf8_filename, Buffer.alloc(0)),
      writeWideStringClumplet(isc_dpb_auth_plugin_name, this.currentPluginName),
      writeWideStringClumplet(isc_dpb_auth_plugin_list, this.buildRemainingPluginList(this.currentPluginName)),
      writeWideClumplet(isc_dpb_specific_auth_data, attachAuthData),
    ]);
  }

  private buildCreateDatabaseDpb(options?: CreateDatabaseOptions): Buffer {
    const pageSize = Buffer.alloc(4);
    pageSize.writeUInt32LE(options?.pageSize ?? 4096, 0);

    return Buffer.concat([
      Buffer.from([isc_dpb_version1]),
      writeTraditionalClumplet(isc_dpb_user_name, Buffer.from(this.options.username, 'utf8')),
      writeTraditionalClumplet(isc_dpb_lc_ctype, Buffer.from('UTF8', 'ascii')),
      writeTraditionalClumplet(isc_dpb_sql_dialect, Buffer.from([3])),
      writeTraditionalClumplet(isc_dpb_page_size, pageSize),
      writeTraditionalClumplet(isc_dpb_overwrite, Buffer.from([options?.overwrite ? 1 : 0])),
      writeTraditionalClumplet(isc_dpb_utf8_filename, Buffer.alloc(0)),
    ]);
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
    options?: CreateDatabaseOptions,
  ): Promise<AttachmentHandle> {
    const dpb = attachAuthData
      ? operation === op_create
        ? this.buildWideCreateDatabaseDpb(attachAuthData, options)
        : this.buildWideAttachDpb(attachAuthData)
      : baseDpb;
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
    const objectId = (await this.channel!.readExactly(8)).readBigInt64BE(0);
    const data = await this.readXdrBuffer();
    const status = parseStatusVector(await this.readStatusVectorBuffer());
    return { handle, objectId, data, status };
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
          chunks.push(await this.channel!.readExactly(length));
        }
      }
    }
    return Buffer.concat(chunks);
  }
}
