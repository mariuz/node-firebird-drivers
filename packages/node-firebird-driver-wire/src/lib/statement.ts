import { AttachmentImpl } from './attachment';
import { ResultSetImpl } from './resultset';
import { TransactionImpl } from './transaction';

import { ExecuteOptions, ExecuteQueryOptions, PrepareOptions, StatementType } from 'node-firebird-driver';
import { AbstractStatement, commonInfo, getPortableInteger, statementInfo } from 'node-firebird-driver/dist/lib/impl';

import { createDataReader, createDataWriter, createDescriptors, DataReader, DataWriter } from './fb-util';

import { StatementHandle } from './wire-protocol';

export class StatementImpl extends AbstractStatement {
  declare attachment: AttachmentImpl;
  declare hasResultSet: boolean;

  statementHandle?: StatementHandle;
  inBuffer = Buffer.alloc(0);
  dataWriter: DataWriter = async () => undefined;
  dataReader: DataReader = async () => [];

  private readonly labelsPromise: Promise<string[]>;
  private readonly typePromise: Promise<StatementType>;

  private constructor(
    attachment: AttachmentImpl,
    readonly inputColumnsLength: number,
    readonly outputColumnsLength: number,
    hasResultSet: boolean,
    labels: string[],
    type: StatementType,
  ) {
    super(attachment);
    this.hasResultSet = hasResultSet;
    this.labelsPromise = Promise.resolve(labels);
    this.typePromise = Promise.resolve(type);
  }

  static async prepare(
    attachment: AttachmentImpl,
    transaction: TransactionImpl,
    sqlStmt: string,
    _options?: PrepareOptions,
  ): Promise<StatementImpl> {
    const statementHandle = await attachment.protocol!.allocateAndPrepareStatement(
      transaction.transactionHandle!,
      sqlStmt,
      3,
    );

    const metadata = attachment.protocol!.getStatementMetadata(statementHandle);
    const statement = new StatementImpl(
      attachment,
      metadata.inputColumns.length,
      metadata.outputColumns.length,
      (metadata.flags & 0x1) !== 0,
      metadata.outputColumns.map((column) => column.alias),
      metadata.type as StatementType,
    );

    statement.statementHandle = statementHandle;
    statement.inBuffer = Buffer.alloc(metadata.inputMessageLength);
    statement.dataWriter = createDataWriter(createDescriptors(metadata.inputColumns));
    statement.dataReader = createDataReader(createDescriptors(metadata.outputColumns));

    return statement;
  }

  protected override async internalDispose(): Promise<void> {
    await this.attachment.protocol!.freeStatement(this.statementHandle!);
    this.statementHandle = undefined;
  }

  protected override async internalExecuteTransaction(_transaction: TransactionImpl): Promise<TransactionImpl> {
    throw new Error('Unimplemented method: executeTransaction.');
  }

  protected override async internalExecute(
    transaction: TransactionImpl,
    parameters?: any[],
    _options?: ExecuteOptions,
  ): Promise<any[]> {
    await this.dataWriter(this.attachment, transaction, this.inBuffer, parameters);

    if (this.hasResultSet) {
      const cursor = await this.attachment.protocol!.openCursor(
        transaction.transactionHandle!,
        this.statementHandle!,
        this.inBuffer,
      );

      try {
        const row = await this.attachment.protocol!.fetchNext(cursor);
        return row ? await this.dataReader(this.attachment, transaction, row) : [];
      } finally {
        await this.attachment.protocol!.closeCursor(this.statementHandle!);
      }
    }

    const output =
      !this.hasResultSet && this.outputColumnsLength > 0
        ? await this.attachment.protocol!.executeStatementReturning(
            transaction.transactionHandle!,
            this.statementHandle!,
            this.inBuffer,
          )
        : await this.attachment.protocol!.executeStatement(
            transaction.transactionHandle!,
            this.statementHandle!,
            this.inBuffer,
          );

    return output ? await this.dataReader(this.attachment, transaction, output) : [];
  }

  protected override async internalExecuteQuery(
    transaction: TransactionImpl,
    parameters?: any[],
    options?: ExecuteQueryOptions,
  ): Promise<ResultSetImpl> {
    return await ResultSetImpl.open(this, transaction, parameters, options);
  }

  override async setCursorName(cursorName: string): Promise<void> {
    await this.attachment.protocol!.setCursorName(this.statementHandle!, cursorName);
  }

  override async getExecPathText(): Promise<string | undefined> {
    const infoRet = await this.attachment.protocol!.getSqlInfo(
      this.statementHandle!,
      Buffer.from([statementInfo.sqlExecPathBlrText]),
    );

    if (infoRet[0] == commonInfo.end) {
      return undefined;
    }

    if (infoRet[0] != statementInfo.sqlExecPathBlrText) {
      throw new Error('Error retrieving statement execution path.');
    }

    const size = getPortableInteger(infoRet.subarray(1), 2);
    return infoRet.subarray(3, 3 + size).toString('utf8');
  }

  override get columnLabels(): Promise<string[]> {
    return this.labelsPromise;
  }

  override get type(): Promise<StatementType> {
    return this.typePromise;
  }
}
