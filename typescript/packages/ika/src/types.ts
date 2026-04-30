import type { IkaClient } from '@ika.xyz/sdk';
import type { Signer as SuiSigner } from '@mysten/sui/cryptography';
import type { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';

/**
 * How the signer obtains the user's secret key share for the dWallet during
 * the centralized sign step.
 *
 * The Ika SDK auto-detects which signing path to use based on which fields
 * are populated, so this config maps directly onto its `requestSign` shape.
 */
export type IkaShareSource =
    | {
          /**
           * The dWallet itself carries `public_user_secret_key_share` (Shared
           * dWallet, or a ZeroTrust dWallet that has had its share made public).
           * No extra data needed — the SDK reads it from the dWallet object.
           */
          kind: 'public-share';
      }
    | {
          /** Use a pre-decrypted user secret key share + the public output. */
          kind: 'secret-share';
          publicOutput: Uint8Array;
          secretShare: Uint8Array;
      }
    | {
          encryptedShareId: string;
          /**
           * Fetch a specific encrypted share from chain by ID and let the Ika
           * SDK decrypt it using `userShareEncryptionKeys` (passed at signer
           * construction). Recommended for ZeroTrust dWallets when the caller
           * has already registered an encryption key under their Sui address.
           */
          kind: 'on-chain-encrypted';
      };

/**
 * Presign strategy.
 *
 * The Ika sign flow needs a one-shot presign capability. With
 * `per-sign-global` the signer issues a fresh global presign on every call
 * (extra round-trip, fully stateless). With `single-provided` the caller
 * supplies a pre-completed `Presign` object — single-use; reconstruct the
 * signer with a fresh presign for each subsequent message.
 */
export type IkaPresignMode =
    | { kind: 'per-sign-global' }
    | { kind: 'single-provided'; presign: import('@ika.xyz/sdk').Presign };

/**
 * How the signer sources the IKA coin used to pay protocol fees.
 */
export type IkaCoinSource =
    | {
          build: (
              tx: import('@mysten/sui/transactions').Transaction,
          ) => import('@mysten/sui/transactions').TransactionObjectArgument;
          /**
           * Caller-supplied builder. Called once per submitted Sui tx
           * (presign + sign), so the caller can split a fresh fee from a
           * master coin each time. Useful when integrating with an existing
           * coin-management strategy.
           */
          kind: 'callback';
      }
    | {
          coinId: string;
          /**
           * Reference an existing on-chain IKA coin by object ID. The Ika move
           * calls take the coin by `&mut`, so the same coin object can be
           * reused across many calls (its balance shrinks each time).
           */
          kind: 'object';
      };

/**
 * Configuration for {@link createIkaSigner}.
 */
export interface IkaSignerConfig {
    /**
     * Optional pre-fetched dWallet object. When omitted, the signer fetches it
     * from chain at construction time via `ikaClient.getDWalletInParticularState`.
     */
    dWallet?: import('@ika.xyz/sdk').SharedDWallet | import('@ika.xyz/sdk').ZeroTrustDWallet;
    /** dWallet object ID. Must be ed25519 (`curve === 2`) and in `Active` state. */
    dWalletId: string;
    /** Pre-built IkaClient (carries the IkaConfig + optional cache). */
    ikaClient: IkaClient;
    /**
     * How to source the IKA coin used to pay protocol fees in each PTB
     * (presign + sign txs).
     *
     * When omitted, the signer auto-discovers IKA coins owned by
     * `suiSigner.toSuiAddress()` via `suiClient.getCoins`, merges them
     * in-PTB if there are several, and uses the result as the fee coin.
     * Throws if the wallet holds no IKA.
     *
     * Override with `{ kind: 'object' }` to pin a specific coin or with
     * `{ kind: 'callback' }` to integrate a custom coin-management strategy.
     */
    ikaCoin?: IkaCoinSource;
    /** Default: `{ kind: 'per-sign-global' }`. */
    presignMode?: IkaPresignMode;
    /** Presign-session poll interval in ms. Default: 2000. */
    presignPollIntervalMs?: number;
    /** Presign-session poll timeout in ms. Default: 60000. */
    presignPollTimeoutMs?: number;
    /** How to source the user secret key share for centralized signing. */
    shareSource: IkaShareSource;
    /** Sign-session poll interval in ms. Default: 1000. */
    signPollIntervalMs?: number;
    /** Sign-session poll timeout in ms. Default: 60000. */
    signPollTimeoutMs?: number;
    /** Sui RPC client used to submit the signing PTB. Should target the same network as `ikaClient`. */
    suiClient: SuiJsonRpcClient;
    /** Sui keypair that pays gas + IKA fees and signs the on-chain Sui txs. */
    suiSigner: SuiSigner;
    /**
     * `UserShareEncryptionKeys` used by the SDK when `shareSource.kind` is
     * `'on-chain-encrypted'` to decrypt the on-chain encrypted share.
     */
    userShareEncryptionKeys?: import('@ika.xyz/sdk').UserShareEncryptionKeys;
}
