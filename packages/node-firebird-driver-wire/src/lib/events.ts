import { AttachmentImpl } from './attachment';
import { EventHandle } from './wire-protocol';

import { AbstractEvents } from 'node-firebird-driver/dist/lib/impl';

export class EventsImpl extends AbstractEvents {
  declare attachment: AttachmentImpl;
  private eventHandle?: EventHandle;

  private constructor(attachment: AttachmentImpl) {
    super(attachment);
  }

  static async queue(
    attachment: AttachmentImpl,
    names: string[],
    callBack: (counters: [string, number][]) => Promise<void>,
  ): Promise<EventsImpl> {
    const events = new EventsImpl(attachment);
    events.eventHandle = await attachment.protocol!.queueEvents(names, callBack);
    return events;
  }

  protected override async internalCancel(): Promise<void> {
    if (!this.eventHandle) {
      return;
    }

    try {
      await this.attachment.protocol!.cancelEvents(this.eventHandle);
    } finally {
      this.eventHandle = undefined;
    }
  }
}
