import { Buffer } from 'node:buffer';

import { authPlugin } from '../constants';
import { legacyHash } from './legacy-hash';
import { SrpClientSession } from './srp';

type AuthPluginName = authPlugin.Name;

export interface ClientAuthPlugin {
  readonly name: AuthPluginName;
  readonly initialData: Buffer;
  continueAuthentication(username: string, password: string, serverData: Buffer): Buffer;
  getSessionKey(): Buffer | undefined;
}

class LegacyAuthPlugin implements ClientAuthPlugin {
  readonly name = 'Legacy_Auth' as const;

  constructor(
    private readonly password: string,
    private readonly charset = 'utf8',
  ) {}

  get initialData(): Buffer {
    return legacyHash(this.password, this.charset);
  }

  continueAuthentication(): Buffer {
    return Buffer.alloc(0);
  }

  getSessionKey(): Buffer | undefined {
    return undefined;
  }
}

class SrpAuthPlugin implements ClientAuthPlugin {
  private readonly session: SrpClientSession;

  constructor(
    readonly name: 'Srp' | 'Srp256',
    proofHashAlgorithm: 'sha1' | 'sha256',
  ) {
    this.session = new SrpClientSession(proofHashAlgorithm);
  }

  get initialData(): Buffer {
    return this.session.getPublicKeyHex();
  }

  continueAuthentication(username: string, password: string, serverData: Buffer): Buffer {
    return this.session.createClientProof(username, password, serverData);
  }

  getSessionKey(): Buffer | undefined {
    return this.session.getSessionKey();
  }
}

export function createAuthPlugin(name: AuthPluginName, password: string): ClientAuthPlugin {
  if (name === 'Legacy_Auth') {
    return new LegacyAuthPlugin(password);
  }

  if (name === 'Srp256') {
    return new SrpAuthPlugin(name, 'sha256');
  }

  return new SrpAuthPlugin(name, 'sha1');
}
