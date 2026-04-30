# @solana/keychain-ika

[Ika dWallet](https://ika.xyz) signer for Solana transactions. Backs a Solana
ed25519 address with a 2PC-MPC dWallet on the Ika network — every signature is
co-produced by the user (centralized party) and the Ika committee (decentralized
party), so no single machine ever holds the full key.

## Installation

```bash
pnpm add @solana/keychain-ika @ika.xyz/sdk @mysten/sui
```

## Prerequisites

1. A pre-provisioned ed25519 dWallet on the Ika network in `Active` state. Use
   the [`ika` CLI](https://docs.ika.xyz) or `@ika.xyz/sdk` directly to run DKG
   / key import; this package does not perform DKG.
2. The dWallet object ID, plus access to the user secret share (one of:
   pre-decrypted bytes, on-chain encrypted share, or a public share for
   `SharedDWallet`).
3. A Sui keypair that owns the dWallet capability and pays Sui gas + Ika fees.

## Usage

### Basic Setup

```typescript
import { createIkaSigner } from '@solana/keychain-ika';
import { getNetworkConfig, IkaClient } from '@ika.xyz/sdk';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';

const network = 'testnet';
const suiClient = new SuiJsonRpcClient({ network, url: 'https://fullnode.testnet.sui.io' });
const ikaClient = new IkaClient({ suiClient, config: getNetworkConfig(network) });
await ikaClient.initialize();

const suiSigner = Ed25519Keypair.fromSecretKey(/* ... */);

const signer = await createIkaSigner({
    ikaClient,
    suiClient,
    suiSigner,
    dWalletId: '0x<dwallet-object-id>',
    shareSource: {
        kind: 'secret-share',
        secretShare: /* Uint8Array */,
        publicOutput: /* Uint8Array */,
    },
});

// Check availability
const ok = await signer.isAvailable();
```

### Signing Transactions

```typescript
import { pipe } from '@solana/functional';
import { signTransaction } from '@solana/signers';

const signed = await signTransaction([signer], transaction);
```

### Signing Messages

```typescript
import { signMessage } from '@solana/signers';

const message = new TextEncoder().encode('Hello, Solana!');
const signature = await signMessage([signer], message);
```

## Configuration

### `IkaSignerConfig`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ikaClient` | `IkaClient` | Yes | Pre-initialized `@ika.xyz/sdk` client |
| `suiClient` | `SuiJsonRpcClient` | Yes | Sui RPC client targeting the same network |
| `suiSigner` | `Signer` | Yes | Sui keypair that pays gas + Ika fees and submits PTBs |
| `dWalletId` | `string` | Yes | Object ID of an Active ed25519 dWallet |
| `shareSource` | `IkaShareSource` | Yes | How to source the user secret share (see below) |
| `userShareEncryptionKeys` | `UserShareEncryptionKeys` | Conditional | Required when `shareSource.kind === 'on-chain-encrypted'` |
| `presignMode` | `IkaPresignMode` | No | `per-sign-global` (default) or `single-provided` |
| `ikaCoin` | `IkaCoinSource` | No | How to source the IKA fee coin (default: `coinWithBalance` with 5 IKA) |
| `dWallet` | `ZeroTrustDWallet \| SharedDWallet` | No | Pre-fetched dWallet to skip the chain lookup |
| `signPollTimeoutMs` / `signPollIntervalMs` | `number` | No | Sign-session polling tuning (default: 60s / 1s) |
| `presignPollTimeoutMs` / `presignPollIntervalMs` | `number` | No | Presign-session polling tuning (default: 60s / 2s) |

### `IkaShareSource` variants

- `{ kind: 'secret-share', secretShare, publicOutput }` — pre-decrypted bytes
- `{ kind: 'on-chain-encrypted', encryptedShareId }` — fetch + decrypt with the `userShareEncryptionKeys` registered for the Sui address
- `{ kind: 'public-share' }` — Shared dWallets, or ZeroTrust dWallets whose share has been made public

### `IkaPresignMode` variants

- `{ kind: 'per-sign-global' }` (default) — a fresh global presign per call (extra round-trip, fully stateless)
- `{ kind: 'single-provided', presign }` — caller supplies a pre-completed `Presign`. Single-use; reconstruct the signer with a fresh presign per message

### `IkaCoinSource` variants

- `{ kind: 'with-balance', balance }` (default budget: 5 IKA) — uses `coinWithBalance` from `@mysten/sui/transactions`. The Sui resolver auto-discovers IKA coins owned by the sender and merges/splits to satisfy `balance`. Pick a value at least as large as one signing-fee charge for the network
- `{ kind: 'object', coinId }` — pin a specific IKA coin object. The Ika move calls take it by `&mut`, so the same coin can be reused until depleted
- `{ kind: 'callback', build }` — caller fully controls coin construction in-PTB

## How It Works

1. **DKG happens out of band.** The dWallet must already exist in `Active` state with an ed25519 public output.
2. **Per call, two Sui PTBs are submitted.** First a presign tx (`request_global_presign`) which the network completes asynchronously; then a sign tx (`request_sign`) carrying the centralized signature share.
3. **The Ika committee finalizes the signature.** The signer polls `getSignInParticularState(..., 'Completed')` and returns the 64-byte ed25519 signature.

## Security Considerations

1. **No DKG inside the signer.** Provision dWallets via the `ika` CLI / SDK; this package only signs.
2. **Curve scope.** Only ed25519 / EdDSA / SHA512 (Solana). Other curves throw at construction.
3. **Mainnet IKA fees.** The default `ikaCoin` budget is 5 IKA — make sure the wallet holds enough, or override the budget. Fees on testnet/devnet are typically zero.
4. **Encrypted shares require a registered encryption key.** The `userShareEncryptionKeys` you pass must match the encryption key registered against `suiSigner.toSuiAddress()` for the dWallet's encrypted share.

## License

MIT
