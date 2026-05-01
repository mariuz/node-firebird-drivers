import * as fs from 'fs-extra-promise';
import * as tmp from 'temp-fs';

// eslint-disable-next-line @typescript-eslint/no-require-imports
require('dotenv').config({ path: '../../.env', quiet: true });

export interface DriverTestConfig {
  username?: string;
  password?: string;
  host?: string;
  port?: number;
  tmpDir?: string;
}

export function loadDriverTestConfig(): DriverTestConfig {
  return {
    username: process.env.ISC_USER ?? 'sysdba',
    password: process.env.ISC_PASSWORD ?? 'masterkey',
    host: process.env.NODE_FB_TEST_HOST ?? 'localhost',
    port: process.env.NODE_FB_TEST_PORT ? parseInt(process.env.NODE_FB_TEST_PORT, 10) : 3050,
    tmpDir: process.env.NODE_FB_TEST_TMP_DIR,
  };
}

export function isLocalDriverTestServer(testConfig: DriverTestConfig): boolean {
  return testConfig.host == undefined || testConfig.host == 'localhost' || testConfig.host == '127.0.0.1';
}

export function ensureDriverTestTmpDir(testConfig: DriverTestConfig): { tmpDir: string; createdTmpDir: boolean } {
  let createdTmpDir = false;

  if (!testConfig.tmpDir) {
    if (!isLocalDriverTestServer(testConfig)) {
      throw new Error('NODE_FB_TEST_TMP_DIR must be set for remote Firebird integration tests.');
    }

    testConfig.tmpDir = tmp.mkdirSync().path.toString();
    createdTmpDir = true;
  }

  if (isLocalDriverTestServer(testConfig)) {
    fs.mkdirpSync(testConfig.tmpDir);
    fs.chmodSync(testConfig.tmpDir, 0o777);
  }

  return { tmpDir: testConfig.tmpDir, createdTmpDir };
}

export function getDriverTestDatabasePath(testConfig: DriverTestConfig, name: string): string {
  if (!testConfig.tmpDir) {
    throw new Error('Test temporary directory is not configured.');
  }

  const extensionIndex = name.lastIndexOf('.');
  const tick = process.hrtime.bigint();
  const databaseName =
    extensionIndex > 0 ? `${name.slice(0, extensionIndex)}-${tick}${name.slice(extensionIndex)}` : `${name}-${tick}`;

  return `${testConfig.tmpDir}/${databaseName}`;
}

export function getDriverTestDatabaseUri(testConfig: DriverTestConfig, name: string): string {
  const database = getDriverTestDatabasePath(testConfig, name);
  return (
    (testConfig.host ?? '') +
    (testConfig.host && testConfig.port ? `/${testConfig.port}` : '') +
    (testConfig.host ? ':' : '') +
    database
  );
}
