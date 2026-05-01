[![CI](https://github.com/asfernandes/node-firebird-drivers/workflows/CI/badge.svg)](https://github.com/asfernandes/node-firebird-drivers/actions?query=workflow%3ACI)
[![npm version](https://badge.fury.io/js/node-firebird-driver-wire.svg)](https://www.npmjs.com/package/node-firebird-driver-wire)

# Firebird high-level wire client for Node.js / TypeScript

`node-firebird-driver-wire` is a modern pure Node.js Firebird client based on the
`node-firebird-driver` API.

Unlike `node-firebird-driver-native`, this package talks directly to the Firebird wire protocol and does not require
the native `fbclient` library to be installed on the machine.

## Installation

```sh
yarn add node-firebird-driver-wire
```

## Usage example

```ts
import { createWireClient } from 'node-firebird-driver-wire';

async function test() {
  const client = createWireClient();

  const attachment = await client.createDatabase('localhost:/tmp/new-db.fdb');
  const transaction = await attachment.startTransaction();

  await attachment.execute(transaction, 'create table t1 (n integer, d date)');
  await transaction.commitRetaining();

  const statement1 = await attachment.prepare(transaction, 'insert into t1 values (?, ?)');
  await statement1.execute(transaction, [1, new Date()]);
  await statement1.execute(transaction, [2, new Date()]);
  await statement1.execute(transaction, [3, new Date()]);
  await statement1.dispose();

  const resultSet = await attachment.executeQuery(transaction, 'select n, d from t1 where n <= ?', [2]);
  const rows = await resultSet.fetch();

  for (const columns of rows) console.log(`n: ${columns[0]}, d: ${columns[1]}`);

  await resultSet.close();

  await transaction.commit();
  await attachment.dropDatabase();

  await client.dispose();
}

test().then(() => console.log('Finish...'));
```

## Connection strings

The wire driver accepts Firebird database URIs in the form:

- `hostname:/path/to/database.fdb`
- `hostname/3051:/path/to/database.fdb`
- `/path/to/database.fdb`
- `C:\\data\\database.fdb`

When no host is provided, the driver defaults to `localhost` and port `3050`.

## Wire driver notes

- Uses the same high-level API exposed by `node-firebird-driver`.
- Does not depend on `fbclient`, which makes it easier to deploy in environments where native libraries are hard to ship.
- Connects through the Firebird network protocol, so it is a good choice for remote database access and containerized deployments.
- Supports Firebird authentication through `Srp256`, `Srp`, and `Legacy_Auth`.
- If you want the Firebird client library or embedded integration instead, use `node-firebird-driver-native`.

You can also configure socket timeout behavior:

```ts
const client = createWireClient({
  timeoutMs: 10000,
});
```

See more examples in [packages/node-firebird-driver/src/test](https://github.com/asfernandes/node-firebird-drivers/tree/master/packages/node-firebird-driver/src/test) and
[packages/node-firebird-driver-wire/src/test](https://github.com/asfernandes/node-firebird-drivers/tree/master/packages/node-firebird-driver-wire/src/test).

# Donation

If this project help you reduce time to develop, you can show your appreciation with a donation.

- GitHub Sponsor: https://github.com/sponsors/asfernandes
- Pix (Brazil): 278dd4e5-8226-494d-93a9-f3fb8a027a99
- BTC: 1Q1W3tLD1xbk81kTeFqobiyrEXcKN1GfHG
- [![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=X3JMTGW92LQEL)
