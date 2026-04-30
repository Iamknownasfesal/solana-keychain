import type { SolanaSigner } from '@solana/keychain-core';
import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { getNetworkConfig, IkaClient, Network } from '@ika.xyz/sdk';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { fromBase64 } from '@mysten/sui/utils';

import { createIkaSigner } from '../ika-signer.js';
import type { IkaSignerConfig } from '../types.js';

const SIGNER_TYPE = 'ika';

/**
 * Required env vars for the live integration test:
 *
 *  - `IKA_NETWORK`           — `'testnet'` or `'mainnet'` (passed to `getNetworkConfig`).
 *  - `SUI_RPC_URL`           — Sui fullnode URL matching that network.
 *  - `SUI_KEYPAIR_BASE64`    — base64-encoded Sui ed25519 keypair (output of
 *                              `sui keytool export <addr> --json | jq .privateKey`,
 *                              or any 32-byte secret-key encoded as base64).
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
    'SUI_KEYPAIR_BASE64',
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

async function buildIkaSigner(): Promise<SolanaSigner> {
    const network = process.env.IKA_NETWORK as Network;
    const ikaConfig = getNetworkConfig(network);
    const suiClient = new SuiJsonRpcClient({
        network: network === 'mainnet' ? 'mainnet' : 'testnet',
        url: process.env.SUI_RPC_URL!,
    });
    const ikaClient = new IkaClient({ config: ikaConfig, suiClient });
    await ikaClient.initialize();

    const suiSigner = Ed25519Keypair.fromSecretKey(fromBase64(process.env.SUI_KEYPAIR_BASE64!));

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
