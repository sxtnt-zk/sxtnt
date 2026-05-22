# @sxtnt_zk/sdk

TypeScript SDK for the **SXTNT folding ZK coprocessor** on Solana.

Build folded measurements client-side, submit them to the on-chain
`ProofRegistry`, and read back per-proof accounts — with the same
byte-exact digest the verifier program recomputes on-chain.

[![npm](https://img.shields.io/npm/v/@sxtnt_zk/sdk?style=flat-square&color=cb3837&label=npm)](https://www.npmjs.com/package/@sxtnt_zk/sdk)
[![Repo](https://img.shields.io/badge/repo-sxtnt--zk%2Fsxtnt-1A2E4A?style=flat-square)](https://github.com/sxtnt-zk/sxtnt)
[![Site](https://img.shields.io/badge/site-sxtnt.fun-D4AF37?style=flat-square)](https://sxtnt.fun)
[![License](https://img.shields.io/badge/license-MIT-F0EDE8?style=flat-square)](https://github.com/sxtnt-zk/sxtnt/blob/main/LICENSE)

## Install

```bash
npm i @sxtnt_zk/sdk
```

Or with `pnpm` / `yarn` / `bun`:

```bash
pnpm add @sxtnt_zk/sdk
yarn  add @sxtnt_zk/sdk
bun   add @sxtnt_zk/sdk
```

Peer-friendly with any modern Solana stack — works alongside the
standard `@solana/web3.js` and `@coral-xyz/anchor` setups.

## Quick start

```ts
import { Connection, PublicKey, Keypair } from "@solana/web3.js";
import { SxtntClient, SchemeKind, proofDigest } from "@sxtnt_zk/sdk";

const connection = new Connection("https://api.mainnet-beta.solana.com");
const client     = new SxtntClient(connection);

// 1. Compute the canonical proof digest client-side — this is the
//    same byte-exact digest the on-chain program will recompute.
const digest = proofDigest({
  finalU:      finalUBytes,      // 32 bytes — final relaxed-R1CS instance
  cZ:          cZBytes,          // 32 bytes — commitment to Z
  cE:          cEBytes,          // 32 bytes — commitment to E
  publicInput: publicInputBytes, // arbitrary length
  steps:       256,              // number of folded sub-proofs
  scheme:      SchemeKind.Nova,
});

// 2. Build the AcceptProof instruction and send it.
const ix = await client.acceptProofInstruction({
  authority:   walletPublicKey,
  scheme:      SchemeKind.Nova,
  finalU:      finalUBytes,
  cZ:          cZBytes,
  cE:          cEBytes,
  publicInput: publicInputBytes,
  digest,
  steps:       256,
});

// 3. Fetch the on-chain AcceptedProof PDA after confirmation.
const acceptedProofPda = client.acceptedProofPda(walletPublicKey, digest);
const accepted         = await client.fetchAcceptedProof(acceptedProofPda);
```

A complete end-to-end walkthrough lives in
[`examples/verify-onchain.ts`](https://github.com/sxtnt-zk/sxtnt/blob/main/examples/verify-onchain.ts).

## What's exported

| Export | Kind | Purpose |
|---|---|---|
| `SxtntClient` | class | Builds `init_registry`, `accept_proof`, and `close_registry` instructions. Derives `ProofRegistry` and `AcceptedProof` PDAs. |
| `proofDigest()` | function | Canonical client-side proof digest. Byte-exact match for the on-chain `proof_digest()` in the Rust verifier. |
| `digestFromHex()` | function | Hex → `Uint8Array` helper for digests stored as strings. |
| `SchemeKind` | enum | `Nova` / `SuperNova` / `HyperNova` scheme selector. The registry records which scheme accepted each proof. |
| `schemeTag()` | function | Stable string tag for a `SchemeKind` (useful for logging and indexers). |
| `CircuitLoader` | class | Loads a circuit definition (relaxed-R1CS constraint set) into a form the on-chain program will accept. |
| `PROGRAM_ID` | `PublicKey` | The deployed SXTNT verifier program ID. Same on devnet and mainnet — `7n5uUZyKVEXfGwgEbVeEQXedqiEigbzKFV9bNDBv74TJ`. |
| `REGISTRY_SEED` | `Uint8Array` | Seed used to derive the per-(authority, scheme) `ProofRegistry` PDA. |
| `PROOF_SEED` | `Uint8Array` | Seed used to derive the per-(registry, digest) `AcceptedProof` PDA. |

The same constants are defined byte-for-byte in
[`crates/onchain/src/lib.rs`](https://github.com/sxtnt-zk/sxtnt/tree/main/crates/onchain).
If your prover lives in another language, match those constants.

## Networks

The SDK does not pin a network. Pass any standard `Connection`. The
verifier program is byte-identical across:

| Network | Endpoint | Program ID |
|---|---|---|
| Mainnet | `https://api.mainnet-beta.solana.com` | `7n5uUZyKVEXfGwgEbVeEQXedqiEigbzKFV9bNDBv74TJ` |
| Devnet  | `https://api.devnet.solana.com`       | `7n5uUZyKVEXfGwgEbVeEQXedqiEigbzKFV9bNDBv74TJ` |

You can verify the deployed program for either network with:

```bash
solana program show 7n5uUZyKVEXfGwgEbVeEQXedqiEigbzKFV9bNDBv74TJ \
  --url mainnet-beta
```

## Building from source

```bash
git clone https://github.com/sxtnt-zk/sxtnt.git
cd sxtnt/sdk/typescript
npm install
npm run build
```

The published artifact under `dist/` is exactly what `npm i` ships.
Build locally if you want to read or modify the source — everything
the package exposes is in the `src/` directory.

## License

[MIT](https://github.com/sxtnt-zk/sxtnt/blob/main/LICENSE). The full
folding-scheme reference implementation and on-chain verifier live at
[github.com/sxtnt-zk/sxtnt](https://github.com/sxtnt-zk/sxtnt).
