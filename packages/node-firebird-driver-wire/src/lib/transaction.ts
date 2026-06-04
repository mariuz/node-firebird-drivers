import { AttachmentImpl } from './attachment';
import { createTpb } from './fb-util';

import { TransactionOptions } from 'node-firebird-driver';
import { AbstractTransaction } from 'node-firebird-driver/dist/lib/impl';

import { TransactionHandle } from './wire-protocol';

export class TransactionImpl extends AbstractTransaction {
  declare attachment: AttachmentImpl;
  transactionHandle?: TransactionHandle;

  static async start(attachment: AttachmentImpl, options?: TransactionOptions): Promise<TransactionImpl> {
    const transaction = new TransactionImpl(attachment);
    transaction.transactionHandle = await attachment.protocol!.startTransaction(createTpb(options));
    return transaction;
  }

  protected override async internalCommit(): Promise<void> {
    await this.attachment.protocol!.commit(this.transactionHandle!);
    this.transactionHandle = undefined;
  }

  protected override async internalCommitRetaining(): Promise<void> {
    await this.attachment.protocol!.commitRetaining(this.transactionHandle!);
  }

  protected override async internalRollback(): Promise<void> {
    await this.attachment.protocol!.rollback(this.transactionHandle!);
    this.transactionHandle = undefined;
  }

  protected override async internalRollbackRetaining(): Promise<void> {
    await this.attachment.protocol!.rollbackRetaining(this.transactionHandle!);
  }
}
