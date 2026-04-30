import { describe, it } from 'vitest';
import { runSignerIntegrationTest } from '@solana/keychain-test-utils';
import { config } from 'dotenv';

import { getConfig } from './setup.js';

config();

// Each scenario performs a full Ika presign + sign round-trip (two Sui txs +
// MPC session polling). On public testnet endpoints this is dominated by
// presign session settlement (~25–35s), so default vitest 30s isn't enough.
const SCENARIO_TIMEOUT_MS = 120_000;

describe('IkaSigner Integration', () => {
    it.skipIf(!process.env.IKA_DWALLET_ID)(
        'signs transactions against a live Ika cluster',
        async () => {
            await runSignerIntegrationTest(await getConfig(['signTransaction']));
        },
        SCENARIO_TIMEOUT_MS,
    );
    it.skipIf(!process.env.IKA_DWALLET_ID)(
        'signs messages against a live Ika cluster',
        async () => {
            await runSignerIntegrationTest(await getConfig(['signMessage']));
        },
        SCENARIO_TIMEOUT_MS,
    );
    it.skipIf(!process.env.IKA_DWALLET_ID)(
        'simulates transactions against a live Ika cluster',
        async () => {
            await runSignerIntegrationTest(await getConfig(['simulateTransaction']));
        },
        SCENARIO_TIMEOUT_MS,
    );
});
