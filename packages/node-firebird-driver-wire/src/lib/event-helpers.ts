import { epb } from 'node-firebird-driver/dist/lib/impl';

export function buildEventBlock(names: readonly string[]): Buffer {
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

export function calculateEventCounts(previous: Buffer, current: Buffer, names: readonly string[]): [string, number][] {
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

export function parseAuxiliaryPort(address: Buffer): number {
  if (address.length < 4) {
    throw new Error('Firebird returned an invalid auxiliary event address.');
  }

  return address.readUInt16BE(2);
}

export function getEventHost(remoteAddress: string | undefined, fallbackHost: string): string {
  if (remoteAddress) {
    return remoteAddress.startsWith('::ffff:') ? remoteAddress.slice('::ffff:'.length) : remoteAddress;
  }

  return fallbackHost;
}
