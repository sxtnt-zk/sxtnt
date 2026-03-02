/**
 * @sxtnt/sdk — TypeScript bindings for the SXTNT folding ZK coprocessor.
 *
 * This package re-exports the four public surfaces:
 *
 *   • `SxtntClient`  — talk to the Solana ProofRegistry program.
 *   • `CircuitLoader` — load circuit templates by id.
 *   • Types          — accumulator / proof / scheme enums shared with the Rust core.
 *
 * Most callers will only need the high-level helpers in `client.ts`.
 * Lower-level building blocks live alongside in `circuit.ts` and
 * `types.ts`.
 */

export { SxtntClient } from "./client.js";
export { CircuitLoader, type CircuitTemplate } from "./circuit.js";
export {
  type FoldingProof,
  type Accumulator,
  type Commitment,
  type FoldStep,
  SchemeKind,
  PROGRAM_ID,
  REGISTRY_SEED,
  PROOF_SEED,
} from "./types.js";

/**
 * Compute the canonical 32-byte proof digest matching the on-chain
 * `proof_digest()` reference in `crates/onchain/src/lib.rs`.
 *
 * The hash binds the scheme tag, the final accumulator's `u`, both
 * commitments, and the public input — in that order.
 */
import { blake3 } from "@noble/hashes/blake3";
import { SchemeKind } from "./types.js";

/** Serialise a SchemeKind enum into the tag byte string the Rust side
 *  uses when seeding the registry PDA. Must stay in lockstep with
 *  `SchemeKind::tag` in `sxtnt-core`.
 */
export function schemeTag(scheme: SchemeKind): Uint8Array {
  switch (scheme) {
    case SchemeKind.Nova:
      return new TextEncoder().encode("nova");
    case SchemeKind.SuperNova:
      return new TextEncoder().encode("supernova");
    case SchemeKind.HyperNova:
      return new TextEncoder().encode("hypernova");
  }
}

/**
 * Compute the canonical proof digest. Matches `proof_digest()` in
 * `crates/onchain/src/lib.rs` byte for byte.
 *
 *   digest = blake3(
 *     "sxtnt.onchain.digest.v1"
 *     || scheme_tag
 *     || final_u
 *     || commitment_z
 *     || commitment_e
 *     || u64_le(public_input.len)
 *     || public_input
 *   )
 */
export function proofDigest(args: {
  scheme: SchemeKind;
  finalU: Uint8Array;
  commitmentZ: Uint8Array;
  commitmentE: Uint8Array;
  publicInput: Uint8Array;
}): Uint8Array {
  if (args.finalU.length !== 32) {
    throw new Error(`finalU must be 32 bytes, got ${args.finalU.length}`);
  }
  if (args.commitmentZ.length !== 64) {
    throw new Error(`commitmentZ must be 64 bytes, got ${args.commitmentZ.length}`);
  }
  if (args.commitmentE.length !== 64) {
    throw new Error(`commitmentE must be 64 bytes, got ${args.commitmentE.length}`);
  }
  const h = blake3.create({});
  h.update(new TextEncoder().encode("sxtnt.onchain.digest.v1"));
  h.update(schemeTag(args.scheme));
  h.update(args.finalU);
  h.update(args.commitmentZ);
  h.update(args.commitmentE);
  const lenBuf = new Uint8Array(8);
  new DataView(lenBuf.buffer).setBigUint64(0, BigInt(args.publicInput.length), true);
  h.update(lenBuf);
  h.update(args.publicInput);
  return h.digest();
}

/**
 * Convenience: convert a hex-encoded digest into the byte array the
 * on-chain instruction expects. Throws on bad input — callers should
 * never trust user-supplied hex blindly.
 */
export function digestFromHex(hex: string): Uint8Array {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (stripped.length !== 64) {
    throw new Error(`expected 32-byte digest (64 hex chars), got ${stripped.length}`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
// kept here so the audit surface is one file.
