import {
  ensureDriverTestTmpDir,
  getDriverTestDatabasePath,
  loadDriverTestConfig,
} from '../../../node-firebird-driver/src/test/test-config';
import { legacyHash } from '../lib/internal/auth/legacy-hash';
import { WireProtocol } from '../lib/internal/wire-protocol';

describe('node-firebird-driver-wire', () => {
  const testConfig = loadDriverTestConfig();
  const username = testConfig.username!;
  const validPassword = testConfig.password!;
  const host = testConfig.host!;
  const port = testConfig.port!;

  function createProtocol(password = validPassword): WireProtocol {
    return new WireProtocol({
      host,
      port,
      username,
      password,
    });
  }

  beforeAll(() => {
    ensureDriverTestTmpDir(testConfig);
  });

  async function withCreatedDatabase<T>(name: string, callback: (database: string) => Promise<T>): Promise<T> {
    const database = getDriverTestDatabasePath(testConfig, name);
    const createProtocolInstance = createProtocol(validPassword);
    const createdAttachment = await createProtocolInstance.createDatabase(database, { overwrite: true });

    try {
      await createProtocolInstance.detach(createdAttachment);
    } finally {
      await createProtocolInstance.close();
    }

    try {
      return await callback(database);
    } finally {
      const dropProtocol = createProtocol(validPassword);
      try {
        const attachment = await dropProtocol.attach(database);
        await dropProtocol.dropDatabase(attachment);
      } finally {
        await dropProtocol.close();
      }
    }
  }

  test('creates, attaches and detaches to a real Firebird database', async () => {
    await withCreatedDatabase('wire-create-attach-detach.fdb', async (database) => {
      const wireProtocol = createProtocol();

      try {
        const wireAttachment = await wireProtocol.attach(database);
        expect(wireAttachment.handle).toBeGreaterThanOrEqual(0);
        await wireProtocol.detach(wireAttachment);
      } finally {
        await wireProtocol.close();
      }
    });
  });

  test('pings a real Firebird database connection', async () => {
    await withCreatedDatabase('wire-ping.fdb', async (database) => {
      const wireProtocol = createProtocol();

      try {
        const wireAttachment = await wireProtocol.attach(database);
        await expect(wireProtocol.ping()).resolves.toBeUndefined();
        await wireProtocol.detach(wireAttachment);
      } finally {
        await wireProtocol.close();
      }
    });
  });

  test('returns a structured Firebird error for a bad password', async () => {
    await withCreatedDatabase('wire-bad-password.fdb', async (database) => {
      const wireProtocol = createProtocol('wrong-password');

      await expect(wireProtocol.attach(database)).rejects.toThrow(/Firebird|gds=/);
      await wireProtocol.close();
    });
  });

  test('legacy hash matches Firebird-compatible vectors', () => {
    expect(legacyHash('masterkey').toString('ascii')).toBe('QP3LMZ/MJh.');
    expect(legacyHash('password').toString('ascii')).toBe('3RNBnBoB0d6');
    expect(legacyHash('12345678').toString('ascii')).toBe('kR2aQutwZAE');
    expect(legacyHash('toolongpassword').toString('ascii')).toBe('Dviq39oEkuI');
  });
});
