/**
 * Shared types. These mirror the Rust structs in `crates/core` and
 * `crates/onchain`. Field names use camelCase on the TypeScript side
 * and snake_case on the Rust side — the Anchor IDL generator handles
 * the conversion automatically when wire-bytes cross the boundary.
 */

import { PublicKey } from "@solana/web3.js";

/** The folding scheme variant. Encoded as a single byte on-chain so
 *  the values here match the Rust `SchemeKind` enum. */
export enum SchemeKind {
  /** Nova: single circuit, relaxed-R1CS. */
  Nova = 0,
  /** SuperNova: N circuits, per-step selector. */
  SuperNova = 1,
  /** HyperNova: CCS-based, batched parallel fold. */
  HyperNova = 2,
}

/** The on-chain program ID for the SXTNT verifier program. Matches the
 *  `declare_id!()` in `crates/onchain/src/program.rs`. */
export const PROGRAM_ID = new PublicKey(
  "7n5uUZyKVEXfGwgEbVeEQXedqiEigbzKFV9bNDBv74TJ",
);

/** PDA seed for the per-(authority, scheme) ProofRegistry. */
export const REGISTRY_SEED = new TextEncoder().encode("sxtnt.registry.v1");

/** PDA seed for an individual AcceptedProof account. */
export const PROOF_SEED = new TextEncoder().encode("sxtnt.proof.v1");

/** A Pedersen commitment — 64 raw bytes (uncompressed bn254 G1). */
export interface Commitment {
  bytes: Uint8Array;
}

/** A relaxed-R1CS accumulator. Mirrors `crates/core/src/accumulator.rs`. */
export interface Accumulator {
  u: Uint8Array;
  commitmentZ: Commitment;
  commitmentE: Commitment;
  step: bigint;
}

/** A single fold step record. */
export interface FoldStep {
  challenge: Uint8Array;
  index: bigint;
}

/** A complete folding proof — what the client posts to the on-chain
 *  registry. */
export interface FoldingProof {
  scheme: SchemeKind;
  finalAcc: Accumulator;
  steps: FoldStep[];
  publicInput: Uint8Array;
}

/** Derive the PDA for a ProofRegistry. Matches `ProofRegistry::pda`
 *  in Rust. */
export function deriveRegistryPda(
  authority: PublicKey,
  scheme: SchemeKind,
): [PublicKey, number] {
  const tag = (() => {
    switch (scheme) {
      case SchemeKind.Nova:
        return new TextEncoder().encode("nova");
      case SchemeKind.SuperNova:
        return new TextEncoder().encode("supernova");
      case SchemeKind.HyperNova:
        return new TextEncoder().encode("hypernova");
    }
  })();
  return PublicKey.findProgramAddressSync(
    [REGISTRY_SEED, authority.toBytes(), tag],
    PROGRAM_ID,
  );
}

/** Derive the PDA for an AcceptedProof. */
export function deriveAcceptedProofPda(
  registry: PublicKey,
  digest: Uint8Array,
): [PublicKey, number] {
  if (digest.length !== 32) {
    throw new Error(`digest must be 32 bytes, got ${digest.length}`);
  }
  return PublicKey.findProgramAddressSync(
    [PROOF_SEED, registry.toBytes(), digest],
    PROGRAM_ID,
  );
}
// transcript domain tag is included one level up.
