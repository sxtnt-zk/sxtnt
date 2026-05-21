//! Off-chain mirrors of the on-chain account types.
//!
//! The Anchor `#[account]` macros in `lib.rs` generate types that drag
//! in the Solana runtime. The structs in this module are plain Rust
//! shapes that the off-chain SDK and the test suite can use without
//! pulling in the BPF-only code paths.
//!
//! `ProofRegistry` here is the off-chain mirror of
//! `RegistryAccount`. `AcceptedProof` mirrors `AcceptedProofAccount`.
//! Both intentionally hold the same field layout so a relying party
//! that reads raw account bytes can deserialise into either.

use solana_program::pubkey::Pubkey;
use sxtnt_core::scheme::SchemeKind;
use thiserror::Error;

use crate::{PROOF_SEED, REGISTRY_SEED};

/// Errors the on-chain program can return. Mapped to Anchor error
/// codes by [`crate::map_err`].
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

/// Off-chain mirror of `RegistryAccount`. Records every accepted
/// folding proof digest under a given authority + scheme. The full
/// proof bytes are stored off-chain; the chain only records the
/// canonical 32-byte digest plus metadata.
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
}
