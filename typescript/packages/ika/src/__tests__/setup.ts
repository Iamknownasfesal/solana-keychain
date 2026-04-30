import type { SolanaSigner } from '@solana/keychain-core';
import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { getNetworkConfig, IkaClient, Network } from '@ika.xyz/sdk';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { createIkaSigner } from '../ika-signer.js';
import type { IkaSignerConfig } from '../types.js';

const SIGNER_TYPE = 'ika';

/**
 * Required env vars for the live integration test:
 *
 *  - `IKA_NETWORK`           — `'testnet'` or `'mainnet'` (passed to `getNetworkConfig`).
 *  - `SUI_RPC_URL`           — Sui fullnode URL matching that network.
 *  - `SUI_KEYPAIR`           — Sui ed25519 secret key (Bech32 `suiprivkey1…`,
 *                              the canonical export format from
 *                              `sui keytool export <addr> --json`).
 *  - `IKA_DWALLET_ID`        — object ID of an Active ed25519 dWallet that the
 *                              keypair is authorised to sign with.
 *  - `IKA_SECRET_SHARE_HEX`  — hex-encoded user secret share for the dWallet.
 *  - `IKA_PUBLIC_OUTPUT_HEX` — hex-encoded `public_output` matching the share.
 *
 * The test is skipped at the call site when `IKA_DWALLET_ID` is unset, so the
 * suite stays green for contributors without an Ika cluster.
 */
const REQUIRED_ENV_VARS = [
    'IKA_NETWORK',
    'SUI_RPC_URL',
    'SUI_KEYPAIR',
    'IKA_DWALLET_ID',
    'IKA_SECRET_SHARE_HEX',
    'IKA_PUBLIC_OUTPUT_HEX',
];

function hexToBytes(hex: string): Uint8Array {
    const stripped = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (stripped.length % 2 !== 0) {
        throw new Error(`Hex string has odd length: ${stripped.length}`);
    }
    const bytes = new Uint8Array(stripped.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

// `runSignerIntegrationTest` calls `createSigner()` once per scenario.
// Memoize so we only do the heavy IkaClient.initialize() multi-object fetch
// once per process — public Sui fullnodes (e.g. testnet.sui.io) rate-limit
// hard otherwise.
let cachedSigner: Promise<SolanaSigner> | undefined;

function buildIkaSigner(): Promise<SolanaSigner> {
    if (!cachedSigner) {
        cachedSigner = (async () => {
            const network = process.env.IKA_NETWORK as Network;
            const ikaConfig = getNetworkConfig(network);
            const suiClient = new SuiJsonRpcClient({
                network: network === 'mainnet' ? 'mainnet' : 'testnet',
                url: process.env.SUI_RPC_URL!,
            });
            const ikaClient = new IkaClient({ config: ikaConfig, suiClient });
            await ikaClient.initialize();

            const suiSigner = Ed25519Keypair.fromSecretKey(process.env.SUI_KEYPAIR!);

            const config: IkaSignerConfig = {
                dWalletId: process.env.IKA_DWALLET_ID!,
                ikaClient,
                shareSource: {
                    kind: 'secret-share',
                    publicOutput: hexToBytes(process.env.IKA_PUBLIC_OUTPUT_HEX!),
                    secretShare: hexToBytes(process.env.IKA_SECRET_SHARE_HEX!),
                },
                suiClient,
                suiSigner,
            };

            return await createIkaSigner(config);
        })();
    }
    return cachedSigner;
}

const CONFIG: SignerTestConfig<SolanaSigner> = {
    createSigner: buildIkaSigner,
    requiredEnvVars: REQUIRED_ENV_VARS,
    signerType: SIGNER_TYPE,
};

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<SolanaSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
