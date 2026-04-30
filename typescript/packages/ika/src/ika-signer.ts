import {
    CoordinatorInnerModule,
    Curve,
    EncryptedUserSecretKeyShare,
    Hash,
    IkaClient,
    IkaTransaction,
    Presign,
    publicKeyFromDWalletOutput,
    SessionsManagerModule,
    SharedDWallet,
    SignatureAlgorithm,
    UserShareEncryptionKeys,
    ZeroTrustDWallet,
} from '@ika.xyz/sdk';
import type { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { coinWithBalance, Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';
import { fromBase64, normalizeSuiAddress } from '@mysten/sui/utils';
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
 * Default per-tx IKA fee budget when `ikaCoin` is omitted. Sized at 5 IKA
 * (assuming 9 decimals), enough headroom to cover at least one sign-session
 * fee on mainnet. Override `ikaCoin` to tighten or loosen.
 */
const DEFAULT_IKA_FEE_BALANCE = 5n * 10n ** 9n;

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
            const signature = await this._signBytes(message.content);
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
            const signature = await this._signBytes(messageBytes);
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
    private async _signBytes(message: Uint8Array): Promise<SignatureBytes> {
        const presign = await this._resolvePresign();
        const shareInputs = await this._requestSignShareInputs();

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

        const ikaCoin = this._buildIkaCoin(suiTx);

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

        const signEvent = await this._executeAndExtractEvent(
            suiTx,
            'SignRequestEvent',
            CoordinatorInnerModule.SignRequestEvent,
        );
        const signId = signEvent.event_data.sign_id;

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
    private async _requestSignShareInputs(): Promise<{
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
                const shareId = this.shareSource.encryptedShareId ?? (await this._resolveOnChainEncryptedShareId());
                const encrypted = await this.ikaClient.getEncryptedUserSecretKeyShare(shareId);
                return { encryptedUserSecretKeyShare: encrypted };
            }
            case 'public-share':
                // SDK auto-detects via dWallet.public_user_secret_key_share — no extras needed.
                return {};
        }
    }

    private async _resolvePresign(): Promise<Presign> {
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
        const ikaCoin = this._buildIkaCoin(presignTx);
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

        const presignEvent = await this._executeAndExtractEvent(
            presignTx,
            'PresignRequestEvent',
            CoordinatorInnerModule.PresignRequestEvent,
        );
        const presignId = presignEvent.event_data.presign_id;

        return await this.ikaClient.getPresignInParticularState(presignId, 'Completed', {
            interval: this.presignPollIntervalMs,
            timeout: this.presignPollTimeoutMs,
        });
    }

    /**
     * Walk the dWallet's `encrypted_user_secret_key_shares` ObjectTable and
     * return the share ID registered against the caller's encryption-key
     * address (`userShareEncryptionKeys.getSuiAddress()`). Used when the
     * caller selects `on-chain-encrypted` mode without pinning an explicit
     * `encryptedShareId`.
     */
    private async _resolveOnChainEncryptedShareId(): Promise<string> {
        if (!this.userShareEncryptionKeys) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message:
                    'Cannot auto-resolve encrypted share without userShareEncryptionKeys; supply encryptedShareId or userShareEncryptionKeys',
            });
        }
        const expected = normalizeSuiAddress(this.userShareEncryptionKeys.getSuiAddress());
        const tableId = this.dWallet.encrypted_user_secret_key_shares.id;

        let cursor: string | null | undefined;
        do {
            const page = await this.suiClient.getDynamicFields({ cursor, parentId: tableId });
            for (const entry of page.data) {
                if (entry.name.type !== 'address') continue;
                const candidate = normalizeSuiAddress(String(entry.name.value));
                if (candidate === expected) return entry.objectId;
            }
            cursor = page.hasNextPage ? page.nextCursor : undefined;
        } while (cursor);

        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            dWalletId: this.dWallet.id,
            encryptionKeyAddress: expected,
            message: `dWallet ${this.dWallet.id} has no encrypted share registered for ${expected}; register one via the Ika SDK first or pass encryptedShareId explicitly`,
        });
    }

    /**
     * Build the IKA coin argument used to pay protocol fees in a single PTB.
     *
     * Default behavior (no `ikaCoin` config) builds a coin via the
     * `coinWithBalance` intent with `balance: 5 IKA` (5 * 10^9) — Sui
     * auto-resolves IKA coins from the sender's wallet and merges/splits to
     * satisfy the budget. Tighten or loosen via `ikaCoin`.
     */
    private _buildIkaCoin(tx: Transaction): TransactionObjectArgument {
        const source = this.ikaCoinSource ?? { balance: DEFAULT_IKA_FEE_BALANCE, kind: 'with-balance' };
        if (source.kind === 'object') {
            return tx.object(source.coinId);
        }
        if (source.kind === 'callback') {
            return source.build(tx);
        }
        const coinType = `${this.ikaClient.ikaConfig.packages.ikaPackage}::ika::IKA`;
        return tx.add(coinWithBalance({ balance: source.balance, type: coinType }));
    }

    /**
     * Sign + execute a Sui transaction with the user's `suiSigner`, locate the
     * MPC initiator event matching `eventTypeSubstring`, and BCS-decode it
     * using the supplied `eventSchema`.
     *
     * Mirrors the canonical pattern used by the Ika SDK's integration helpers:
     * read `event.bcs` (base64) and parse via
     * `SessionsManagerModule.DWalletSessionEvent(<inner>)`. This is more robust
     * than walking `parsedJson` because BCS schemas survive field renames in
     * the Move source.
     */
    private async _executeAndExtractEvent<
        TInner extends Parameters<typeof SessionsManagerModule.DWalletSessionEvent>[0],
    >(
        suiTx: Transaction,
        eventTypeSubstring: string,
        innerSchema: TInner,
    ): Promise<ReturnType<ReturnType<typeof SessionsManagerModule.DWalletSessionEvent<TInner>>['parse']>> {
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

        const event = result.events?.find(candidate => candidate.type.includes(eventTypeSubstring));
        if (!event?.bcs) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                eventType: eventTypeSubstring,
                message: `Sui tx executed but no ${eventTypeSubstring} (with bcs payload) found in events`,
            });
        }
        return SessionsManagerModule.DWalletSessionEvent(innerSchema).parse(fromBase64(event.bcs));
    }
}
