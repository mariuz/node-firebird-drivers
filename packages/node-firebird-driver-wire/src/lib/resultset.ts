import { StatementImpl } from './statement';
import { TransactionImpl } from './transaction';

import { ExecuteQueryOptions, FetchOptions } from 'node-firebird-driver';
import { AbstractResultSet } from 'node-firebird-driver/dist/lib/impl';

import { CursorHandle } from './wire-protocol';

export class ResultSetImpl extends AbstractResultSet {
  declare statement: StatementImpl;
  declare transaction: TransactionImpl;

  cursor?: CursorHandle;
  delayedError: unknown;

  static async open(
    statement: StatementImpl,
    transaction: TransactionImpl,
    parameters?: any[],
    _options?: ExecuteQueryOptions,
  ): Promise<ResultSetImpl> {
    const resultSet = new ResultSetImpl(statement, transaction);

    await statement.dataWriter(statement.attachment, transaction, statement.inBuffer, parameters);

    resultSet.cursor = await statement.attachment.protocol!.openCursor(
      transaction.transactionHandle!,
      statement.statementHandle!,
      statement.inBuffer,
    );

    return resultSet;
  }

  protected override async internalClose(): Promise<void> {
    await this.statement.attachment.protocol!.closeCursor(this.statement.statementHandle!);
    this.cursor = undefined;
  }

  protected override async internalFetch(options?: FetchOptions): Promise<{ finished: boolean; rows: any[][] }> {
    if (this.delayedError) {
      const delayedError = this.delayedError;
      this.delayedError = undefined;
      throw delayedError;
    }

    const rows: any[][] = [];
    const fetchSize = options?.fetchSize;

    while (!fetchSize || rows.length < fetchSize) {
      let buffer: Buffer | undefined;

      try {
        buffer = await this.statement.attachment.protocol!.fetchNext(this.cursor!);
      } catch (error) {
        if (rows.length === 0) {
          throw error;
        }

        this.delayedError = error;
        return { finished: false, rows };
      }

      if (!buffer) {
        return { finished: true, rows };
      }

      rows.push(await this.statement.dataReader(this.statement.attachment, this.transaction, buffer));
    }

    return { finished: false, rows };
  }
}
