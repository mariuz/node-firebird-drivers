import { dpb } from 'node-firebird-driver/dist/lib/impl';

import { authPlugin } from './constants';
import { DpbClumplet } from './protocol-types';
import { writeWideClumplet, writeWideStringClumplet } from './xdr';

type AuthPluginName = authPlugin.Name;

export function buildConnectPluginList(): string {
  return authPlugin.list.join(',');
}

export function buildRemainingPluginList(currentPluginName: AuthPluginName): string {
  const index = authPlugin.list.indexOf(currentPluginName);
  return index === -1 ? currentPluginName : authPlugin.list.slice(index).join(',');
}

export function normalizeLogin(login: string): string {
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

export function readDpbClumplets(buffer: Buffer): DpbClumplet[] {
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

export function buildAttachmentDpb(
  baseDpb: Buffer,
  attachAuthData: Buffer | undefined,
  currentPluginName: AuthPluginName,
): Buffer {
  if (!attachAuthData) {
    return baseDpb;
  }

  const clumplets = readDpbClumplets(baseDpb).filter(
    ({ tag }) => tag !== dpb.auth_plugin_name && tag !== dpb.auth_plugin_list && tag !== dpb.specific_auth_data,
  );

  const parts = [Buffer.from([dpb.version2]), ...clumplets.map(({ tag, value }) => writeWideClumplet(tag, value))];

  if (!clumplets.some(({ tag }) => tag === dpb.utf8_filename)) {
    parts.push(writeWideClumplet(dpb.utf8_filename, Buffer.alloc(0)));
  }

  parts.push(writeWideStringClumplet(dpb.auth_plugin_name, currentPluginName));
  parts.push(writeWideStringClumplet(dpb.auth_plugin_list, buildRemainingPluginList(currentPluginName)));
  parts.push(writeWideClumplet(dpb.specific_auth_data, attachAuthData));

  return Buffer.concat(parts);
}

export function writeMultiPartConnectParameter(parameterType: number, value: Buffer): Buffer {
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
