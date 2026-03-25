/**
 * SxtntClient — high-level helpers for talking to the on-chain
 * ProofRegistry program.
 *
 * The client wraps a `@solana/web3.js` Connection plus a wallet and
 * exposes three operations:
 *
 *   • `initRegistry`  — create a fresh per-(authority, scheme) registry.
 *   • `acceptProof`   — submit a canonical proof digest for verification.
 *   • `fetchRegistry` — read the current state of a registry.
 *
 * The actual instruction encoding lives behind an `AnchorProvider`
 * since the IDL ships alongside the production program. This module
 * pins the program ID and the PDA derivations so the SDK and the
 * Rust side cannot drift.
 */

import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  type Signer,
} from "@solana/web3.js";
import {
  Accumulator,
  PROGRAM_ID,
  SchemeKind,
  deriveAcceptedProofPda,
  deriveRegistryPda,
} from "./types.js";
import { proofDigest } from "./index.js";

/** Returned by `fetchRegistry`. */
export interface RegistryState {
  authority: PublicKey;
  scheme: SchemeKind;
  proofCount: bigint;
  latestDigest: Uint8Array;
  bump: number;
}

/**
 * The high-level SXTNT client. Construct one per session.
 */
export class SxtntClient {
  readonly connection: Connection;
  readonly programId: PublicKey;

  constructor(connection: Connection, programId: PublicKey = PROGRAM_ID) {
    this.connection = connection;
    this.programId = programId;
  }

  /**
   * Build the instruction for `init_registry`. Caller is responsible
   * for adding it to a transaction and submitting it through their
   * wallet adapter.
   */
  initRegistryIx(
    authority: PublicKey,
    scheme: SchemeKind,
  ): TransactionInstruction {
    const [registry] = deriveRegistryPda(authority, scheme);
    const data = Buffer.from([0, scheme & 0xff]); // tag byte + scheme
    return new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: authority, isSigner: true, isWritable: true },
        { pubkey: registry, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });
  }

  /**
   * Build the instruction for `accept_proof`. Recomputes the canonical
   * digest client-side so callers cannot accidentally post a stale
   * digest that no longer matches its components.
   */
  acceptProofIx(args: {
    authority: PublicKey;
    payer: PublicKey;
    scheme: SchemeKind;
    finalAcc: Accumulator;
    publicInput: Uint8Array;
    steps: number;
  }): { ix: TransactionInstruction; digest: Uint8Array; registry: PublicKey } {
    const [registry] = deriveRegistryPda(args.authority, args.scheme);
    const digest = proofDigest({
      scheme: args.scheme,
      finalU: args.finalAcc.u,
      commitmentZ: args.finalAcc.commitmentZ.bytes,
      commitmentE: args.finalAcc.commitmentE.bytes,
      publicInput: args.publicInput,
    });
    const [accepted] = deriveAcceptedProofPda(registry, digest);
    const data = Buffer.concat([
      Buffer.from([1]), // accept_proof tag
      Buffer.from(args.finalAcc.u),
      Buffer.from(args.finalAcc.commitmentZ.bytes),
      Buffer.from(args.finalAcc.commitmentE.bytes),
      Buffer.from(uint32LE(args.publicInput.length)),
      Buffer.from(args.publicInput),
      Buffer.from(digest),
      Buffer.from(uint32LE(args.steps)),
    ]);
    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: args.authority, isSigner: true, isWritable: false },
        { pubkey: registry, isSigner: false, isWritable: true },
        { pubkey: accepted, isSigner: false, isWritable: true },
        { pubkey: args.payer, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });
    return { ix, digest, registry };
  }

  /**
   * Compose a one-shot transaction that submits a proof digest. The
   * caller is expected to sign with both authority and payer.
   */
  async submitProof(args: {
    authority: Signer;
    payer: Signer;
    scheme: SchemeKind;
    finalAcc: Accumulator;
    publicInput: Uint8Array;
    steps: number;
  }): Promise<string> {
    const { ix } = this.acceptProofIx({
      authority: args.authority.publicKey,
      payer: args.payer.publicKey,
      scheme: args.scheme,
      finalAcc: args.finalAcc,
      publicInput: args.publicInput,
      steps: args.steps,
    });
    const tx = new Transaction().add(ix);
    const { blockhash } = await this.connection.getLatestBlockhash();
    tx.recentBlockhash = blockhash;
    tx.feePayer = args.payer.publicKey;
    tx.sign(args.authority, args.payer);
    return this.connection.sendRawTransaction(tx.serialize());
  }

  /**
   * Fetch the current state of a registry. Returns `null` if the
   * account does not exist yet.
   */
  async fetchRegistry(
    authority: PublicKey,
    scheme: SchemeKind,
  ): Promise<RegistryState | null> {
    const [pda] = deriveRegistryPda(authority, scheme);
    const acct = await this.connection.getAccountInfo(pda);
    if (!acct) {
      return null;
    }
    return decodeRegistry(acct.data);
  }
}

function uint32LE(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

function decodeRegistry(data: Uint8Array): RegistryState {
  // 8 (discriminator) + 32 (authority) + 1 (scheme) + 8 (count) + 32 (digest) + 1 (bump)
  if (data.length < 82) {
    throw new Error(`registry account too small: ${data.length} bytes`);
  }
  const authority = new PublicKey(data.subarray(8, 40));
  const scheme = data[40] as SchemeKind;
  const proofCount = new DataView(data.buffer, data.byteOffset + 41, 8).getBigUint64(0, true);
  const latestDigest = data.slice(49, 81);
  const bump = data[81];
  return { authority, scheme, proofCount, latestDigest, bump };
}
// kept here so the audit surface is one file.
