import {
  ensureDriverTestTmpDir,
  getDriverTestDatabasePath,
  loadDriverTestConfig,
} from '../../../node-firebird-driver/src/test/test-config';
import { tpb } from '../../../node-firebird-driver/src/lib/impl/fb-util';
import {
  isc_dpb_lc_ctype,
  isc_dpb_overwrite,
  isc_dpb_page_size,
  isc_dpb_sql_dialect,
  isc_dpb_user_name,
  isc_dpb_utf8_filename,
  isc_dpb_version1,
} from '../lib/internal/constants';
import { legacyHash } from '../lib/internal/auth/legacy-hash';
import { WireProtocol } from '../lib/internal/wire-protocol';
import { writeTraditionalClumplet } from '../lib/internal/xdr';

describe('node-firebird-driver-wire', () => {
  const testConfig = loadDriverTestConfig();
  const username = testConfig.username!;
  const validPassword = testConfig.password!;
  const host = testConfig.host!;
  const port = testConfig.port!;

  function createAttachDpb(): Buffer {
    return Buffer.concat([
      Buffer.from([isc_dpb_version1]),
      writeTraditionalClumplet(isc_dpb_user_name, Buffer.from(username, 'utf8')),
      writeTraditionalClumplet(isc_dpb_lc_ctype, Buffer.from('UTF8', 'ascii')),
      writeTraditionalClumplet(isc_dpb_utf8_filename, Buffer.alloc(0)),
    ]);
  }

  function createDatabaseDpb(overwrite = false): Buffer {
    const pageSize = Buffer.alloc(4);
    pageSize.writeUInt32LE(4096, 0);

    return Buffer.concat([
      Buffer.from([isc_dpb_version1]),
      writeTraditionalClumplet(isc_dpb_user_name, Buffer.from(username, 'utf8')),
      writeTraditionalClumplet(isc_dpb_lc_ctype, Buffer.from('UTF8', 'ascii')),
      writeTraditionalClumplet(isc_dpb_sql_dialect, Buffer.from([3])),
      writeTraditionalClumplet(isc_dpb_page_size, pageSize),
      writeTraditionalClumplet(isc_dpb_overwrite, Buffer.from([overwrite ? 1 : 0])),
      writeTraditionalClumplet(isc_dpb_utf8_filename, Buffer.alloc(0)),
    ]);
  }

  function createTpb(): Buffer {
    return Buffer.from([tpb.version1, tpb.concurrency, tpb.wait, tpb.write]);
  }

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
    const uniqueName = `${name.replace(/\.fdb$/i, '')}-${process.pid}-${Date.now()}-${Math.random()
      .toString(16)
      .slice(2)}.fdb`;
    const database = getDriverTestDatabasePath(testConfig, uniqueName);
    const createProtocolInstance = createProtocol(validPassword);
    const createdAttachment = await createProtocolInstance.createDatabase(database, createDatabaseDpb(true));

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
        const attachment = await dropProtocol.attach(database, createAttachDpb());
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
        const wireAttachment = await wireProtocol.attach(database, createAttachDpb());
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
        const wireAttachment = await wireProtocol.attach(database, createAttachDpb());
        await expect(wireProtocol.ping()).resolves.toBeUndefined();
        await wireProtocol.detach(wireAttachment);
      } finally {
        await wireProtocol.close();
      }
    });
  });

  test('starts a transaction with a TPB', async () => {
    await withCreatedDatabase('wire-start-transaction.fdb', async (database) => {
      const wireProtocol = createProtocol();

      try {
        await wireProtocol.attach(database, createAttachDpb());
        const transaction = await wireProtocol.startTransaction(createTpb());
        expect(transaction.handle).toBeGreaterThanOrEqual(0);
      } finally {
        await wireProtocol.close();
      }
    });
  });

  test('commits and rolls back transactions', async () => {
    await withCreatedDatabase('wire-commit-rollback-transaction.fdb', async (database) => {
      const wireProtocol = createProtocol();

      try {
        const attachment = await wireProtocol.attach(database, createAttachDpb());
        const transaction1 = await wireProtocol.startTransaction(createTpb());
        expect(transaction1.handle).toBeGreaterThanOrEqual(0);
        await wireProtocol.commit(transaction1);

        const transaction2 = await wireProtocol.startTransaction(createTpb());
        expect(transaction2.handle).toBeGreaterThanOrEqual(0);
        await wireProtocol.rollback(transaction2);

        await wireProtocol.detach(attachment);
      } finally {
        await wireProtocol.close();
      }
    });
  });

  test('commits and rolls back retaining transactions', async () => {
    await withCreatedDatabase('wire-retaining-transaction.fdb', async (database) => {
      const wireProtocol = createProtocol();

      try {
        const attachment = await wireProtocol.attach(database, createAttachDpb());

        const transaction1 = await wireProtocol.startTransaction(createTpb());
        expect(transaction1.handle).toBeGreaterThanOrEqual(0);
        await wireProtocol.commitRetaining(transaction1);
        await wireProtocol.rollback(transaction1);

        const transaction2 = await wireProtocol.startTransaction(createTpb());
        expect(transaction2.handle).toBeGreaterThanOrEqual(0);
        await wireProtocol.rollbackRetaining(transaction2);
        await wireProtocol.commit(transaction2);

        await wireProtocol.detach(attachment);
      } finally {
        await wireProtocol.close();
      }
    });
  });

  test('allocates, prepares and frees a statement', async () => {
    await withCreatedDatabase('wire-prepare-statement.fdb', async (database) => {
      const wireProtocol = createProtocol();

      try {
        const attachment = await wireProtocol.attach(database, createAttachDpb());
        const transaction = await wireProtocol.startTransaction(createTpb());
        const statement = await wireProtocol.allocateStatement();

        await wireProtocol.prepareStatement(transaction, statement, 'create table t1 (n1 integer)');
        await wireProtocol.freeStatement(statement);
        await wireProtocol.rollback(transaction);
        await wireProtocol.detach(attachment);
      } finally {
        await wireProtocol.close();
      }
    });
  });

  test('executes a prepared statement without a result set', async () => {
    await withCreatedDatabase('wire-execute-statement.fdb', async (database) => {
      const wireProtocol = createProtocol();

      try {
        const attachment = await wireProtocol.attach(database, createAttachDpb());
        const transaction = await wireProtocol.startTransaction(createTpb());
        const statement1 = await wireProtocol.allocateStatement();
        const statement2 = await wireProtocol.allocateStatement();

        try {
          await wireProtocol.prepareStatement(transaction, statement1, 'create table t1 (n1 integer)');
          await wireProtocol.executeStatement(transaction, statement1);

          await wireProtocol.prepareStatement(transaction, statement2, 'create table t1 (n1 integer)');
          await expect(wireProtocol.executeStatement(transaction, statement2)).rejects.toThrow(/Firebird|exist/);
        } finally {
          await wireProtocol.freeStatement(statement2);
          await wireProtocol.freeStatement(statement1);
        }

        await wireProtocol.rollback(transaction);
        await wireProtocol.detach(attachment);
      } finally {
        await wireProtocol.close();
      }
    });
  });

  test('returns a structured Firebird error for invalid SQL preparation', async () => {
    await withCreatedDatabase('wire-invalid-prepare.fdb', async (database) => {
      const wireProtocol = createProtocol();

      try {
        const attachment = await wireProtocol.attach(database, createAttachDpb());
        const transaction = await wireProtocol.startTransaction(createTpb());
        const statement = await wireProtocol.allocateStatement();

        try {
          await expect(
            wireProtocol.prepareStatement(transaction, statement, 'create select t1 (n1 integer)'),
          ).rejects.toThrow(/Firebird|Dynamic SQL Error|SQL error code/);
        } finally {
          await wireProtocol.freeStatement(statement);
        }

        await wireProtocol.rollback(transaction);
        await wireProtocol.detach(attachment);
      } finally {
        await wireProtocol.close();
      }
    });
  });

  test('returns a structured Firebird error for a bad password', async () => {
    await withCreatedDatabase('wire-bad-password.fdb', async (database) => {
      const wireProtocol = createProtocol('wrong-password');

      await expect(wireProtocol.attach(database, createAttachDpb())).rejects.toThrow(/Firebird|gds=/);
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
