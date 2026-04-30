import {
    Curve,
    EncryptedUserSecretKeyShare,
    Hash,
    IkaClient,
    IkaTransaction,
    Presign,
    publicKeyFromDWalletOutput,
    SharedDWallet,
    SignatureAlgorithm,
    UserShareEncryptionKeys,
    ZeroTrustDWallet,
} from '@ika.xyz/sdk';
import type { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';
import { Address, address as addressFromBase58, getAddressDecoder } from '@solana/addresses';
import {
    assertSignatureValid,
    createSignatureDictionary,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
import {
    Transaction as SolanaTransaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';

import type { IkaCoinSource, IkaPresignMode, IkaShareSource, IkaSignerConfig } from './types.js';

const ED25519_CURVE_NUMBER = 2;
const DEFAULT_SIGN_POLL_TIMEOUT_MS = 60_000;
const DEFAULT_SIGN_POLL_INTERVAL_MS = 1_000;
const DEFAULT_PRESIGN_POLL_TIMEOUT_MS = 60_000;
const DEFAULT_PRESIGN_POLL_INTERVAL_MS = 2_000;

/**
 * Create an Ika dWallet-backed signer for Solana ed25519 signing.
 *
 * The dWallet must already exist on the Ika network in `Active` state, with
 * `curve === ED25519`. DKG / key import / share registration all happen
 * out-of-band via the `ika` CLI or the Ika TypeScript SDK directly.
 *
 * Each `signMessages` / `signTransactions` call submits two Sui transactions:
 * one to provision (or reuse) a presign capability, then a second to call
 * `request_sign` and surface the resulting 64-byte Ed25519 signature once the
 * Ika MPC network completes the sign session.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when `dWalletId` is not active or
 * uses a non-ed25519 curve.
 * @throws {SignerError} `SIGNER_INITIALIZATION_FAILED` /
 * `SIGNER_REMOTE_API_ERROR` when the dWallet object cannot be fetched.
 */
export async function createIkaSigner<TAddress extends string = string>(
    config: IkaSignerConfig,
): Promise<SolanaSigner<TAddress>> {
    return await IkaSigner.create<TAddress>(config);
}

export class IkaSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;

    private readonly ikaClient: IkaClient;
    private readonly suiClient: SuiJsonRpcClient;
    private readonly suiSigner: IkaSignerConfig['suiSigner'];
    private readonly dWallet: SharedDWallet | ZeroTrustDWallet;
    private readonly shareSource: IkaShareSource;
    private readonly userShareEncryptionKeys: UserShareEncryptionKeys | undefined;
    private readonly presignMode: IkaPresignMode;
    private readonly ikaCoinSource: IkaCoinSource | undefined;
    private readonly signPollTimeoutMs: number;
    private readonly signPollIntervalMs: number;
    private readonly presignPollTimeoutMs: number;
    private readonly presignPollIntervalMs: number;
    private providedPresignConsumed = false;

    private constructor(
        config: IkaSignerConfig,
        address: Address<TAddress>,
        dWallet: SharedDWallet | ZeroTrustDWallet,
    ) {
        this.address = address;
        this.ikaClient = config.ikaClient;
        this.suiClient = config.suiClient;
        this.suiSigner = config.suiSigner;
        this.dWallet = dWallet;
        this.shareSource = config.shareSource;
        this.userShareEncryptionKeys = config.userShareEncryptionKeys;
        this.presignMode = config.presignMode ?? { kind: 'per-sign-global' };
        this.ikaCoinSource = config.ikaCoin;
        this.signPollTimeoutMs = config.signPollTimeoutMs ?? DEFAULT_SIGN_POLL_TIMEOUT_MS;
        this.signPollIntervalMs = config.signPollIntervalMs ?? DEFAULT_SIGN_POLL_INTERVAL_MS;
        this.presignPollTimeoutMs = config.presignPollTimeoutMs ?? DEFAULT_PRESIGN_POLL_TIMEOUT_MS;
        this.presignPollIntervalMs = config.presignPollIntervalMs ?? DEFAULT_PRESIGN_POLL_INTERVAL_MS;
    }

    static async create<TAddress extends string = string>(config: IkaSignerConfig): Promise<IkaSigner<TAddress>> {
        if (!config.ikaClient || !config.suiClient || !config.suiSigner || !config.dWalletId) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required configuration fields (ikaClient, suiClient, suiSigner, or dWalletId)',
            });
        }
        if (config.shareSource.kind === 'on-chain-encrypted' && !config.userShareEncryptionKeys) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: "shareSource 'on-chain-encrypted' requires userShareEncryptionKeys to be supplied",
            });
        }

        let dWallet: SharedDWallet | ZeroTrustDWallet;
        try {
            const fetched =
                config.dWallet ??
                ((await config.ikaClient.getDWalletInParticularState(config.dWalletId, 'Active')) as
                    | SharedDWallet
                    | ZeroTrustDWallet);
            dWallet = fetched;
        } catch (error) {
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                cause: error,
                message: `Failed to fetch dWallet ${config.dWalletId} from Ika`,
            });
        }

        if (dWallet.curve !== ED25519_CURVE_NUMBER) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                actual: dWallet.curve,
                expected: ED25519_CURVE_NUMBER,
                message: `dWallet ${config.dWalletId} is not ed25519 (curve=${dWallet.curve}); IkaSigner only supports Solana-compatible ed25519 dWallets`,
            });
        }

        const publicOutput = dWallet.state.Active?.public_output;
        if (!publicOutput) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: `dWallet ${config.dWalletId} has no Active.public_output; cannot derive public key`,
            });
        }
        const publicOutputBytes = Uint8Array.from(publicOutput);

        let pubkeyBytes: Uint8Array;
        try {
            pubkeyBytes = await publicKeyFromDWalletOutput(Curve.ED25519, publicOutputBytes);
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: `Failed to derive ed25519 public key from dWallet ${config.dWalletId}`,
            });
        }
        if (pubkeyBytes.length !== 32) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                length: pubkeyBytes.length,
                message: `Expected 32-byte ed25519 public key, got ${pubkeyBytes.length} bytes`,
            });
        }

        const addressString = getAddressDecoder().decode(pubkeyBytes);
        const address = addressFromBase58(addressString) as Address<TAddress>;

        return new IkaSigner<TAddress>(config, address, dWallet);
    }

    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        const result: SignatureDictionary[] = [];
        for (const message of messages) {
            const signature = await this.#signBytes(message.content);
            await assertSignatureValid({
                data: message.content,
                signature,
                signerAddress: this.address,
            });
            result.push(createSignatureDictionary({ signature, signerAddress: this.address }));
        }
        return result;
    }

    async signTransactions(
        transactions: readonly (SolanaTransaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        const result: SignatureDictionary[] = [];
        for (const transaction of transactions) {
            const messageBytes = new Uint8Array(transaction.messageBytes);
            const signature = await this.#signBytes(messageBytes);
            await assertSignatureValid({
                data: messageBytes,
                signature,
                signerAddress: this.address,
            });
            result.push(createSignatureDictionary({ signature, signerAddress: this.address }));
        }
        return result;
    }

    async isAvailable(): Promise<boolean> {
        try {
            await this.ikaClient.getEpoch();
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Run the full Ika sign flow for a single message and return the raw
     * 64-byte Ed25519 signature.
     */
    async #signBytes(message: Uint8Array): Promise<SignatureBytes> {
        const presign = await this.#resolvePresign();
        const shareInputs = await this.#requestSignShareInputs();

        const suiTx = new Transaction();
        const ikaTx = new IkaTransaction({
            ikaClient: this.ikaClient,
            transaction: suiTx,
            userShareEncryptionKeys: this.userShareEncryptionKeys,
        });

        const messageApproval = ikaTx.approveMessage({
            curve: Curve.ED25519,
            dWalletCap: this.dWallet.dwallet_cap_id,
            hashScheme: Hash.SHA512,
            message,
            signatureAlgorithm: SignatureAlgorithm.EdDSA,
        });
        const verifiedPresignCap = ikaTx.verifyPresignCap({ presign });

        const ikaCoin = await this.#buildIkaCoin(suiTx);

        await ikaTx.requestSign({
            dWallet: this.dWallet,
            hashScheme: Hash.SHA512,
            messageApproval,
            presign,
            verifiedPresignCap,
            ...shareInputs,
            ikaCoin,
            message,
            signatureScheme: SignatureAlgorithm.EdDSA,
            suiCoin: suiTx.gas,
        });

        const signId = await this.#executeAndExtractEventId(suiTx, 'SignRequestEvent', 'sign_id');

        const signObject = await this.ikaClient.getSignInParticularState(
            signId,
            Curve.ED25519,
            SignatureAlgorithm.EdDSA,
            'Completed',
            { interval: this.signPollIntervalMs, timeout: this.signPollTimeoutMs },
        );
        const signatureArray = signObject.state.Completed?.signature;
        if (!signatureArray) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Sign session completed without a signature',
                signId,
            });
        }
        const signature = Uint8Array.from(signatureArray);
        if (signature.length !== 64) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                length: signature.length,
                message: `Expected 64-byte ed25519 signature, got ${signature.length} bytes`,
            });
        }
        return signature as SignatureBytes;
    }

    /**
     * Resolve the named arguments `IkaTransaction.requestSign` uses to
     * auto-detect which signing path to take (encrypted / explicit / public).
     */
    async #requestSignShareInputs(): Promise<{
        encryptedUserSecretKeyShare?: EncryptedUserSecretKeyShare;
        publicOutput?: Uint8Array;
        secretShare?: Uint8Array;
    }> {
        switch (this.shareSource.kind) {
            case 'secret-share':
                return {
                    publicOutput: this.shareSource.publicOutput,
                    secretShare: this.shareSource.secretShare,
                };
            case 'on-chain-encrypted': {
                const encrypted = await this.ikaClient.getEncryptedUserSecretKeyShare(
                    this.shareSource.encryptedShareId,
                );
                return { encryptedUserSecretKeyShare: encrypted };
            }
            case 'public-share':
                // SDK auto-detects via dWallet.public_user_secret_key_share — no extras needed.
                return {};
        }
    }

    async #resolvePresign(): Promise<Presign> {
        if (this.presignMode.kind === 'single-provided') {
            if (this.providedPresignConsumed) {
                throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message:
                        'IkaPresignMode.single-provided was already consumed; reconstruct IkaSigner with a fresh presign or use per-sign-global mode',
                });
            }
            this.providedPresignConsumed = true;
            return this.presignMode.presign;
        }

        const networkKey = await this.ikaClient.getLatestNetworkEncryptionKey();

        const presignTx = new Transaction();
        const ikaTx = new IkaTransaction({
            ikaClient: this.ikaClient,
            transaction: presignTx,
        });
        const ikaCoin = await this.#buildIkaCoin(presignTx);
        const unverifiedPresignCap = ikaTx.requestGlobalPresign({
            curve: Curve.ED25519,
            dwalletNetworkEncryptionKeyId: networkKey.id,
            ikaCoin,
            signatureAlgorithm: SignatureAlgorithm.EdDSA,
            suiCoin: presignTx.gas,
        });
        // The cap object must be either consumed in-PTB or transferred to the
        // sender so it persists. Transfer it to the signer address; the next
        // sign tx will re-fetch + verify it.
        const senderAddress = this.suiSigner.toSuiAddress();
        presignTx.transferObjects([unverifiedPresignCap], senderAddress);

        const presignId = await this.#executeAndExtractEventId(presignTx, 'PresignRequestEvent', 'presign_id');

        return await this.ikaClient.getPresignInParticularState(presignId, 'Completed', {
            interval: this.presignPollIntervalMs,
            timeout: this.presignPollTimeoutMs,
        });
    }

    /**
     * Build the IKA coin argument used to pay protocol fees in a single PTB.
     *
     * Default behavior (no `ikaCoin` config) is to query the wallet for IKA
     * coins via `suiClient.getCoins`, merge them in-PTB if there are several
     * (so the move call sees a single coin with the wallet's full balance),
     * and return the merged coin. Move calls take the coin by `&mut`, so
     * leftover balance stays in the same on-chain object.
     */
    async #buildIkaCoin(tx: Transaction): Promise<TransactionObjectArgument> {
        const source = this.ikaCoinSource;
        if (source?.kind === 'object') {
            return tx.object(source.coinId);
        }
        if (source?.kind === 'callback') {
            return source.build(tx);
        }

        const owner = this.suiSigner.toSuiAddress();
        const coinType = `${this.ikaClient.ikaConfig.packages.ikaPackage}::ika::IKA`;
        const { data: coins } = await this.suiClient.getCoins({ coinType, owner });
        const [head, ...rest] = coins;
        if (!head) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                coinType,
                message: `Wallet ${owner} holds no ${coinType} coins to pay Ika protocol fees with`,
                owner,
            });
        }
        const primary = tx.object(head.coinObjectId);
        if (rest.length > 0) {
            tx.mergeCoins(
                primary,
                rest.map(coin => tx.object(coin.coinObjectId)),
            );
        }
        return primary;
    }

    /**
     * Sign + execute a Sui transaction with the user's `suiSigner`, then walk
     * the resulting events to find the named MPC event and pull `idField` out
     * of its parsed JSON.
     */
    async #executeAndExtractEventId(suiTx: Transaction, eventTypeSubstring: string, idField: string): Promise<string> {
        let result;
        try {
            result = await this.suiClient.signAndExecuteTransaction({
                options: { showEvents: true },
                signer: this.suiSigner,
                transaction: suiTx,
            });
        } catch (error) {
            throwSignerError(SignerErrorCode.HTTP_ERROR, {
                cause: error,
                message: `Failed to execute Sui transaction (looking for ${eventTypeSubstring})`,
            });
        }

        const events = result.events ?? [];
        for (const event of events) {
            if (!event.type.includes(eventTypeSubstring)) continue;
            const parsed = event.parsedJson as Record<string, unknown> | undefined;
            const eventData = parsed?.event_data as Record<string, unknown> | undefined;
            const candidate = eventData?.[idField] ?? parsed?.[idField];
            if (typeof candidate === 'string') return candidate;
        }
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            eventType: eventTypeSubstring,
            field: idField,
            message: `Sui tx executed but no ${eventTypeSubstring}.${idField} found in events`,
        });
    }
}
