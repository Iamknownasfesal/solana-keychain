import { generateKeyPairSigner } from '@solana/signers';
import { assertIsSolanaSigner } from '@solana/keychain-core';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { IkaSigner } from '../ika-signer.js';
import type { IkaSignerConfig } from '../types.js';

/**
 * Stand-in pubkey returned by the mocked `publicKeyFromDWalletOutput`. The
 * actual bytes don't matter for these tests — we only use them to derive an
 * `Address` value that the signer attaches to itself.
 */
let mockPubkey: Uint8Array = new Uint8Array(32).fill(1);

vi.mock('@ika.xyz/sdk', async importOriginal => {
    const mod = await importOriginal<typeof import('@ika.xyz/sdk')>();
    return {
        ...mod,
        publicKeyFromDWalletOutput: vi.fn(async () => mockPubkey),
    };
});

vi.mock('@solana/keychain-core', async importOriginal => {
    const mod = await importOriginal<typeof import('@solana/keychain-core')>();
    return {
        ...mod,
        assertSignatureValid: vi.fn(),
    };
});

const ED25519_CURVE = 2;
const ANOTHER_CURVE = 0;

interface DWalletStub {
    curve: number;
    dwallet_cap_id: string;
    id: string;
    state: {
        Active?: { public_output: number[] };
        $kind?: string;
    };
}

function makeDWallet(overrides: Partial<DWalletStub> = {}): DWalletStub {
    return {
        curve: ED25519_CURVE,
        dwallet_cap_id: '0xcap',
        id: '0xdwallet',
        state: {
            Active: { public_output: Array.from(new Uint8Array(64).fill(2)) },
            $kind: 'Active',
        },
        ...overrides,
    };
}

function makeIkaClient(overrides: Partial<Record<string, unknown>> = {}) {
    return {
        ikaConfig: { packages: { ikaPackage: '0xika' } },
        getDWalletInParticularState: vi.fn(async () => makeDWallet()),
        getDWallet: vi.fn(async () => makeDWallet()),
        getEpoch: vi.fn(async () => 1),
        getEncryptedUserSecretKeyShare: vi.fn(),
        getLatestNetworkEncryptionKey: vi.fn(),
        getPresignInParticularState: vi.fn(),
        getSignInParticularState: vi.fn(),
        ...overrides,
    };
}

function makeSuiClient() {
    return {
        signAndExecuteTransaction: vi.fn(),
        getCoins: vi.fn(),
    };
}

function makeSuiSigner() {
    return { toSuiAddress: () => '0xsuiaddress' };
}

function makeConfig(overrides: Partial<IkaSignerConfig> = {}): IkaSignerConfig {
    return {
        dWalletId: '0xdwallet',
        ikaClient: makeIkaClient() as unknown as IkaSignerConfig['ikaClient'],
        shareSource: { kind: 'public-share' },
        suiClient: makeSuiClient() as unknown as IkaSignerConfig['suiClient'],
        suiSigner: makeSuiSigner() as unknown as IkaSignerConfig['suiSigner'],
        ...overrides,
    };
}

describe('IkaSigner', () => {
    beforeEach(() => {
        mockPubkey = new Uint8Array(32).fill(1);
        vi.clearAllMocks();
    });

    describe('create', () => {
        it('creates a SolanaSigner from a valid ed25519 dWallet', async () => {
            const expected = await generateKeyPairSigner();
            // Re-use the keypair signer's address by feeding its raw pubkey
            // through the mocked derivation.
            mockPubkey = await import('@solana/addresses').then(
                ({ getAddressEncoder }) => new Uint8Array(getAddressEncoder().encode(expected.address)),
            );

            const signer = await IkaSigner.create(makeConfig());

            expect(signer.address).toBe(expected.address);
            expect(typeof signer.signMessages).toBe('function');
            expect(typeof signer.signTransactions).toBe('function');
            expect(typeof signer.isAvailable).toBe('function');
            assertIsSolanaSigner(signer);
        });

        it('uses pre-fetched dWallet when supplied (skips chain lookup)', async () => {
            const ikaClient = makeIkaClient();
            const config = makeConfig({
                dWallet: makeDWallet() as unknown as IkaSignerConfig['dWallet'],
                ikaClient: ikaClient as unknown as IkaSignerConfig['ikaClient'],
            });
            await IkaSigner.create(config);
            expect(ikaClient.getDWalletInParticularState).not.toHaveBeenCalled();
        });

        describe('config validation', () => {
            it.each([
                ['ikaClient', { ikaClient: undefined }],
                ['suiClient', { suiClient: undefined }],
                ['suiSigner', { suiSigner: undefined }],
                ['dWalletId', { dWalletId: '' }],
            ] as const)('throws CONFIG_ERROR when %s is missing', async (_field, override) => {
                await expect(IkaSigner.create(makeConfig(override as Partial<IkaSignerConfig>))).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('Missing required configuration fields'),
                });
            });

            it('throws CONFIG_ERROR when shareSource is on-chain-encrypted without userShareEncryptionKeys', async () => {
                await expect(
                    IkaSigner.create(
                        makeConfig({
                            shareSource: { kind: 'on-chain-encrypted', encryptedShareId: '0xshare' },
                        }),
                    ),
                ).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('userShareEncryptionKeys'),
                });
            });

            it('throws CONFIG_ERROR when dWallet curve is not ed25519', async () => {
                const ikaClient = makeIkaClient({
                    getDWalletInParticularState: vi.fn(async () => makeDWallet({ curve: ANOTHER_CURVE })),
                });
                await expect(
                    IkaSigner.create(makeConfig({ ikaClient: ikaClient as unknown as IkaSignerConfig['ikaClient'] })),
                ).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('not ed25519'),
                });
            });

            it('throws CONFIG_ERROR when dWallet has no Active.public_output', async () => {
                const ikaClient = makeIkaClient({
                    getDWalletInParticularState: vi.fn(async () =>
                        makeDWallet({ state: { Active: undefined, $kind: 'Active' } }),
                    ),
                });
                await expect(
                    IkaSigner.create(makeConfig({ ikaClient: ikaClient as unknown as IkaSignerConfig['ikaClient'] })),
                ).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('public_output'),
                });
            });
        });

        describe('parsing errors', () => {
            it('throws PARSING_ERROR when derived pubkey is not 32 bytes', async () => {
                mockPubkey = new Uint8Array(20);
                await expect(IkaSigner.create(makeConfig())).rejects.toMatchObject({
                    code: 'SIGNER_PARSING_ERROR',
                    message: expect.stringContaining('Expected 32-byte ed25519 public key'),
                });
            });

            it('throws PARSING_ERROR when publicKeyFromDWalletOutput throws', async () => {
                const sdk = await import('@ika.xyz/sdk');
                const spy = vi
                    .mocked(sdk.publicKeyFromDWalletOutput)
                    .mockRejectedValueOnce(new Error('decode failure'));
                await expect(IkaSigner.create(makeConfig())).rejects.toMatchObject({
                    code: 'SIGNER_PARSING_ERROR',
                    message: expect.stringContaining('Failed to derive ed25519 public key'),
                });
                spy.mockReset();
            });
        });

        describe('remote api errors', () => {
            it('throws REMOTE_API_ERROR when getDWalletInParticularState fails', async () => {
                const ikaClient = makeIkaClient({
                    getDWalletInParticularState: vi.fn(async () => {
                        throw new Error('rpc unreachable');
                    }),
                });
                await expect(
                    IkaSigner.create(makeConfig({ ikaClient: ikaClient as unknown as IkaSignerConfig['ikaClient'] })),
                ).rejects.toMatchObject({
                    code: 'SIGNER_REMOTE_API_ERROR',
                    message: expect.stringContaining('Failed to fetch dWallet'),
                });
            });
        });
    });

    describe('isAvailable', () => {
        it('returns true when the Ika network responds to getEpoch', async () => {
            const ikaClient = makeIkaClient();
            const signer = await IkaSigner.create(
                makeConfig({ ikaClient: ikaClient as unknown as IkaSignerConfig['ikaClient'] }),
            );
            await expect(signer.isAvailable()).resolves.toBe(true);
            expect(ikaClient.getEpoch).toHaveBeenCalledOnce();
        });

        it('returns false when getEpoch throws', async () => {
            const ikaClient = makeIkaClient({
                getEpoch: vi.fn(async () => {
                    throw new Error('network down');
                }),
            });
            const signer = await IkaSigner.create(
                makeConfig({ ikaClient: ikaClient as unknown as IkaSignerConfig['ikaClient'] }),
            );
            await expect(signer.isAvailable()).resolves.toBe(false);
        });
    });
});
