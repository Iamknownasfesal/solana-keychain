import { describe, it } from 'vitest';
import { runSignerIntegrationTest } from '@solana/keychain-test-utils';
import { config } from 'dotenv';

import { getConfig } from './setup.js';

config();

describe('IkaSigner Integration', () => {
    it.skipIf(!process.env.IKA_DWALLET_ID)('signs transactions against a live Ika cluster', async () => {
        await runSignerIntegrationTest(await getConfig(['signTransaction']));
    });
    it.skipIf(!process.env.IKA_DWALLET_ID)('signs messages against a live Ika cluster', async () => {
        await runSignerIntegrationTest(await getConfig(['signMessage']));
    });
    it.skipIf(!process.env.IKA_DWALLET_ID)('simulates transactions against a live Ika cluster', async () => {
        await runSignerIntegrationTest(await getConfig(['simulateTransaction']));
    });
});
