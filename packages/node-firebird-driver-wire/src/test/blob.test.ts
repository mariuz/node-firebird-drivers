import { BlobSeekWhence } from 'node-firebird-driver';

import { BlobStreamImpl } from '../lib/blob';

describe('BlobStreamImpl', () => {
  test('seeks relative to the current write position', async () => {
    const protocol = {
      createBlob: jest.fn().mockResolvedValue({
        handle: 1,
        id: Buffer.alloc(8),
      }),
      putSegment: jest.fn().mockResolvedValue(undefined),
      seekBlob: jest.fn().mockResolvedValue(4),
    };

    const attachment = {
      protocol,
      isValid: true,
    } as any;

    const transaction = {
      transactionHandle: {
        handle: 1,
      },
    } as any;

    const blobStream = await BlobStreamImpl.create(attachment, transaction);

    await blobStream.write(Buffer.from('12345'));
    expect(await blobStream.seek(-1, BlobSeekWhence.CURRENT)).toBe(4);

    expect(protocol.putSegment).toHaveBeenCalledTimes(1);
    expect(protocol.seekBlob).toHaveBeenCalledWith(blobStream.blobHandle, BlobSeekWhence.START, 4);
  });
});
