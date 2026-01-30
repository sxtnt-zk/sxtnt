//! sxtnt-onchain
//!
//! Solana on-chain verifier interface for SXTNT folding proofs.
//!
//! This crate describes the account layout, the instruction set, and
//! the verifier glue the deployed `sxtnt` program will use. It is a
//! reference implementation — the live devnet program lives in a
//! separate (currently private) repository and shares this exact
//! shape.
//!
//! The crate compiles both as a `cdylib` (the Solana BPF target) and
//! as a regular Rust library (so the test suite and the SDK can
//! import the account structs without dragging in the BPF entrypoint).

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(missing_docs)]

pub mod program;

use solana_program::pubkey::Pubkey;
use sxtnt_core::scheme::SchemeKind;
use thiserror::Error;

/// The fixed seed used to derive the [`ProofRegistry`] PDA. Every
/// authority gets exactly one registry per (authority, scheme) pair.
pub const REGISTRY_SEED: &[u8] = b"sxtnt.registry.v1";

/// The fixed seed for the per-proof PDA. Derived from the proof's
/// blake3 digest so two clients cannot collide on submission.
pub const PROOF_SEED: &[u8] = b"sxtnt.proof.v1";

/// Errors the on-chain program can return. The Anchor `error_code`
/// macro maps these to numeric codes in `program.rs`.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OnchainError {
    /// The supplied proof digest did not match the recomputed digest.
    #[error("proof digest mismatch")]
    DigestMismatch,
    /// The registry was already initialised by a different authority.
    #[error("registry already initialised")]
    AlreadyInitialized,
    /// The scheme tag did not match the registry's configured scheme.
    #[error("scheme mismatch")]
    SchemeMismatch,
    /// The proof was rejected by the off-chain verifier interface.
    /// On-chain the program checks the canonical digest; the full
    /// relaxed-R1CS replay lives in `sxtnt-verifier`.
    #[error("verifier rejection")]
    VerifierRejection,
    /// A required signer was missing.
    #[error("missing signer")]
    MissingSigner,
    /// The instruction was malformed.
    #[error("malformed instruction data")]
    MalformedInstruction,
}

/// The on-chain account that records every accepted folding proof
/// digest under a given authority + scheme. The full proof bytes are
/// stored off-chain (`api.sxtnt.fun /folding/simulate`); the chain
/// only records the canonical 32-byte digest plus metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofRegistry {
    /// The authority that may append proofs to this registry.
    pub authority: Pubkey,
    /// Which folding scheme this registry accepts.
    pub scheme: SchemeKind,
    /// Monotonically increasing counter of accepted proofs.
    pub proof_count: u64,
    /// The latest accepted proof digest. Useful for clients that
    /// only need the tip of the log.
    pub latest_digest: [u8; 32],
    /// The bump seed used to derive the PDA.
    pub bump: u8,
}

impl ProofRegistry {
    /// Derive the PDA for a given (authority, scheme) pair.
    pub fn pda(authority: &Pubkey, scheme: SchemeKind, program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[REGISTRY_SEED, authority.as_ref(), scheme.tag()],
            program_id,
        )
    }
}

/// A single recorded proof. One account per accepted proof, addressed
/// by `(registry, digest)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedProof {
    /// Pointer back to the registry that accepted this proof.
    pub registry: Pubkey,
    /// The canonical 32-byte digest (blake3 of the serialised proof).
    pub digest: [u8; 32],
    /// The slot at which this proof was accepted.
    pub accepted_slot: u64,
    /// The number of fold steps recorded in the proof.
    pub steps: u32,
    /// The PDA bump.
    pub bump: u8,
}

impl AcceptedProof {
    /// PDA for a single accepted proof.
    pub fn pda(registry: &Pubkey, digest: &[u8; 32], program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[PROOF_SEED, registry.as_ref(), digest], program_id)
    }
}

/// Compute the canonical digest the on-chain program checks against.
/// The digest binds the scheme kind, the final accumulator's `u` /
/// commitments, and the public input, in that order.
pub fn proof_digest(
    scheme: SchemeKind,
    final_u: &[u8; 32],
    commitment_z: &[u8; 64],
    commitment_e: &[u8; 64],
    public_input: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"sxtnt.onchain.digest.v1");
    h.update(scheme.tag());
    h.update(final_u);
    h.update(commitment_z);
    h.update(commitment_e);
    h.update(&(public_input.len() as u64).to_le_bytes());
    h.update(public_input);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_pda_is_deterministic() {
        let auth = Pubkey::new_unique();
        let prog = Pubkey::new_unique();
        let (pda1, bump1) = ProofRegistry::pda(&auth, SchemeKind::Nova, &prog);
        let (pda2, bump2) = ProofRegistry::pda(&auth, SchemeKind::Nova, &prog);
        assert_eq!(pda1, pda2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn scheme_changes_pda() {
        let auth = Pubkey::new_unique();
        let prog = Pubkey::new_unique();
        let (nova, _) = ProofRegistry::pda(&auth, SchemeKind::Nova, &prog);
        let (sn, _) = ProofRegistry::pda(&auth, SchemeKind::SuperNova, &prog);
        assert_ne!(nova, sn);
    }

    #[test]
    fn digest_is_stable() {
        let d1 = proof_digest(
            SchemeKind::Nova,
            &[1u8; 32],
            &[2u8; 64],
            &[3u8; 64],
            b"pi",
        );
        let d2 = proof_digest(
            SchemeKind::Nova,
            &[1u8; 32],
            &[2u8; 64],
            &[3u8; 64],
            b"pi",
        );
        assert_eq!(d1, d2);
    }
}
// transcript domain tag is included one level up.
