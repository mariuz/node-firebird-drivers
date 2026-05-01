import { parseDatabaseUri } from '../lib/attachment';

describe('parseDatabaseUri', () => {
  test('preserves a hostless Windows drive path', () => {
    expect(parseDatabaseUri('C:\\data\\db.fdb')).toEqual({
      host: 'localhost',
      port: 3050,
      database: 'C:\\data\\db.fdb',
    });
  });

  test('still parses an explicit host and port before a Windows drive path', () => {
    expect(parseDatabaseUri('dbhost/3051:C:\\data\\db.fdb')).toEqual({
      host: 'dbhost',
      port: 3051,
      database: 'C:\\data\\db.fdb',
    });
  });
});
