/**
 * End-to-end TypeScript example: build a canonical proof digest and
 * submit it to the on-chain ProofRegistry.
 *
 * This example uses a stub accumulator — replace `finalAcc` with the
 * accumulator returned by your prover. The point is to show the wire
 * shape the client expects.
 *
 * Run with:
 *
 *   tsx examples/verify-onchain.ts
 */

import {
  Connection,
  Keypair,
  clusterApiUrl,
} from "@solana/web3.js";
import { SxtntClient, SchemeKind, proofDigest } from "../sdk/typescript/src/index.js";

async function main() {
  // The reference verifier interface lives at api.sxtnt.fun and on
  // Solana devnet under the program id in `src/types.ts`. Switch the
  // cluster to mainnet-beta once the production verifier ships.
  const connection = new Connection(clusterApiUrl("devnet"), "confirmed");
  const client = new SxtntClient(connection);

  // Authority + payer. In production these come from the wallet
  // adapter; here we generate ephemeral keypairs for illustration.
  const authority = Keypair.generate();
  const payer = authority;

  // The finalAcc shape: 32-byte `u`, 64-byte commitments. Production
  // callers replace these with the bytes returned by `Nova::prove` on
  // the Rust side (which `sdk/typescript` will wrap when the WASM
  // bindings ship).
  const finalAcc = {
    u: new Uint8Array(32).fill(1),
    commitmentZ: { bytes: new Uint8Array(64).fill(2) },
    commitmentE: { bytes: new Uint8Array(64).fill(3) },
    step: 4n,
  };
  const publicInput = new TextEncoder().encode("public.inputs.bytes");

  const digest = proofDigest({
    scheme: SchemeKind.Nova,
    finalU: finalAcc.u,
    commitmentZ: finalAcc.commitmentZ.bytes,
    commitmentE: finalAcc.commitmentE.bytes,
    publicInput,
  });
  console.log("digest:", Buffer.from(digest).toString("hex"));

  const { ix, registry } = client.acceptProofIx({
    authority: authority.publicKey,
    payer: payer.publicKey,
    scheme: SchemeKind.Nova,
    finalAcc,
    publicInput,
    steps: 4,
  });
  console.log("registry pda:", registry.toBase58());
  console.log("ix length:", ix.data.length);

  // In production:
  //   const sig = await client.submitProof({ authority, payer, ... });
  //   console.log("sig:", sig);
  // The example stops short of actually sending so it runs offline.
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
