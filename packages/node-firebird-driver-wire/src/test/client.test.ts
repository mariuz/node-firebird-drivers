import { createWireClient } from '../lib';

import { runCommonTests } from '../../../node-firebird-driver/src/test/tests';

const client = createWireClient();

runCommonTests(client);
