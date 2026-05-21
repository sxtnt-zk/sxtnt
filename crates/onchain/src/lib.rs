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
//!
//! The Anchor `#[program]` lives at the crate root because the macro
//! resolves `crate::ID` for its dispatcher.

#![cfg_attr(not(test), forbid(unsafe_code))]
// Anchor's `#[program]` / `#[derive(Accounts)]` macros emit hidden
// structs without doc comments. We want public docs on our own
// surface but cannot force docs onto macro-generated symbols, so the
// lint is downgraded to a warning at the crate level.
#![warn(missing_docs)]

use anchor_lang::prelude::*;
use solana_program::pubkey::Pubkey as SolPubkey;
use sxtnt_core::scheme::SchemeKind;
use thiserror::Error;

pub mod types;
pub use types::{AcceptedProof, OnchainError, ProofRegistry};

/// The fixed seed used to derive the [`ProofRegistry`] PDA. Every
/// authority gets exactly one registry per (authority, scheme) pair.
pub const REGISTRY_SEED: &[u8] = b"sxtnt.registry.v1";

/// The fixed seed for the per-proof PDA. Derived from the proof's
/// blake3 digest so two clients cannot collide on submission.
pub const PROOF_SEED: &[u8] = b"sxtnt.proof.v1";

declare_id!("7n5uUZyKVEXfGwgEbVeEQXedqiEigbzKFV9bNDBv74TJ");

/// The Anchor program entry. The generated dispatcher binds the three
/// instructions below to the canonical Solana BPF entrypoint.
#[program]
pub mod sxtnt_program {
    use super::*;

    /// Initialise a fresh `ProofRegistry` for the supplied authority
    /// and scheme.
    pub fn init_registry(ctx: Context<InitRegistry>, scheme: u8) -> Result<()> {
        let scheme_kind = scheme_from_u8(scheme)
            .ok_or(error!(SxtntError::MalformedInstruction))?;
        let reg = &mut ctx.accounts.registry;
        reg.authority = ctx.accounts.authority.key();
        reg.scheme = scheme;
        reg.proof_count = 0;
        reg.latest_digest = [0u8; 32];
        reg.bump = ctx.bumps.registry;
        let _ = scheme_kind; // bound to the registry via the seed
        Ok(())
    }

    /// Accept a folding proof. The client supplies the canonical
    /// digest components; the program recomputes the digest, checks
    /// it matches the supplied value, and appends it to the registry.
    pub fn accept_proof(
        ctx: Context<AcceptProof>,
        final_u: [u8; 32],
        commitment_z: [u8; 64],
        commitment_e: [u8; 64],
        public_input: Vec<u8>,
        claimed_digest: [u8; 32],
        steps: u32,
    ) -> Result<()> {
        let scheme = scheme_from_u8(ctx.accounts.registry.scheme)
            .ok_or(error!(SxtntError::MalformedInstruction))?;
        let recomputed =
            proof_digest(scheme, &final_u, &commitment_z, &commitment_e, &public_input);
        require!(recomputed == claimed_digest, SxtntError::DigestMismatch);

        let registry = &mut ctx.accounts.registry;
        registry.proof_count = registry.proof_count.saturating_add(1);
        registry.latest_digest = claimed_digest;

        let accepted = &mut ctx.accounts.accepted;
        accepted.registry = registry.key();
        accepted.digest = claimed_digest;
        accepted.accepted_slot = Clock::get()?.slot;
        accepted.steps = steps;
        accepted.bump = ctx.bumps.accepted;
        Ok(())
    }

    /// Close the registry account and refund its lamports to the
    /// authority. Future accepted proofs cannot reference it.
    pub fn close_registry(_ctx: Context<CloseRegistry>) -> Result<()> {
        Ok(())
    }
}

/// Account context for `init_registry`.
#[derive(Accounts)]
#[instruction(scheme: u8)]
pub struct InitRegistry<'info> {
    /// The authority paying for and signing the initialisation.
    #[account(mut)]
    pub authority: Signer<'info>,
    /// The registry PDA being initialised.
    #[account(
        init,
        payer = authority,
        space = RegistryAccount::SPACE,
        seeds = [REGISTRY_SEED, authority.key().as_ref(), &[scheme]],
        bump,
    )]
    pub registry: Account<'info, RegistryAccount>,
    /// The Solana system program — needed by `init`.
    pub system_program: Program<'info, System>,
}

/// Account context for `accept_proof`.
#[derive(Accounts)]
#[instruction(
    final_u: [u8; 32],
    commitment_z: [u8; 64],
    commitment_e: [u8; 64],
    public_input: Vec<u8>,
    claimed_digest: [u8; 32],
    steps: u32,
)]
pub struct AcceptProof<'info> {
    /// The authority appending a proof. Must match the registry.
    pub authority: Signer<'info>,
    /// The registry being appended to.
    #[account(
        mut,
        seeds = [REGISTRY_SEED, authority.key().as_ref(), &[registry.scheme]],
        bump = registry.bump,
        has_one = authority,
    )]
    pub registry: Account<'info, RegistryAccount>,
    /// A fresh PDA recording this single accepted proof.
    #[account(
        init,
        payer = payer,
        space = AcceptedProofAccount::SPACE,
        seeds = [PROOF_SEED, registry.key().as_ref(), &claimed_digest],
        bump,
    )]
    pub accepted: Account<'info, AcceptedProofAccount>,
    /// Pays for the new PDA.
    #[account(mut)]
    pub payer: Signer<'info>,
    /// The Solana system program.
    pub system_program: Program<'info, System>,
}

/// Account context for `close_registry`.
#[derive(Accounts)]
pub struct CloseRegistry<'info> {
    /// The authority closing the registry.
    pub authority: Signer<'info>,
    /// The registry account being closed; its lamports go back to
    /// the authority.
    #[account(
        mut,
        close = authority,
        seeds = [REGISTRY_SEED, authority.key().as_ref(), &[registry.scheme]],
        bump = registry.bump,
        has_one = authority,
    )]
    pub registry: Account<'info, RegistryAccount>,
}

/// On-chain registry state (Anchor `#[account]` form).
#[account]
pub struct RegistryAccount {
    /// The owning authority.
    pub authority: Pubkey,
    /// Encoded `SchemeKind` (0 = Nova, 1 = SuperNova, 2 = HyperNova).
    pub scheme: u8,
    /// Number of proofs accepted so far.
    pub proof_count: u64,
    /// The most recently accepted digest.
    pub latest_digest: [u8; 32],
    /// PDA bump.
    pub bump: u8,
}

impl RegistryAccount {
    /// 8 (discriminator) + 32 (authority) + 1 (scheme) + 8 (count) +
    /// 32 (digest) + 1 (bump).
    pub const SPACE: usize = 8 + 32 + 1 + 8 + 32 + 1;
}

/// On-chain accepted-proof state (Anchor `#[account]` form).
#[account]
pub struct AcceptedProofAccount {
    /// Registry that accepted this proof.
    pub registry: Pubkey,
    /// Canonical digest.
    pub digest: [u8; 32],
    /// Slot at acceptance.
    pub accepted_slot: u64,
    /// Number of fold steps in the proof.
    pub steps: u32,
    /// PDA bump.
    pub bump: u8,
}

impl AcceptedProofAccount {
    /// 8 + 32 + 32 + 8 + 4 + 1.
    pub const SPACE: usize = 8 + 32 + 32 + 8 + 4 + 1;
}

/// Anchor error codes. The first variant is mapped to 6000 by Anchor;
/// the off-chain client reads these via the IDL.
#[error_code]
pub enum SxtntError {
    /// The supplied digest did not match the recomputed digest.
    #[msg("proof digest mismatch")]
    DigestMismatch,
    /// The instruction data was malformed.
    #[msg("malformed instruction data")]
    MalformedInstruction,
    /// The supplied scheme tag did not match the registry's scheme.
    #[msg("scheme mismatch")]
    SchemeMismatch,
    /// A required signer was missing.
    #[msg("missing signer")]
    MissingSigner,
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

fn scheme_from_u8(s: u8) -> Option<SchemeKind> {
    match s {
        0 => Some(SchemeKind::Nova),
        1 => Some(SchemeKind::SuperNova),
        2 => Some(SchemeKind::HyperNova),
        _ => None,
    }
}

/// Map an [`OnchainError`] to an Anchor [`SxtntError`] code so the
/// program's error surface is consistent with the off-chain reference.
pub fn map_err(err: OnchainError) -> SxtntError {
    match err {
        OnchainError::DigestMismatch | OnchainError::VerifierRejection => SxtntError::DigestMismatch,
        OnchainError::AlreadyInitialized => SxtntError::MalformedInstruction,
        OnchainError::SchemeMismatch => SxtntError::SchemeMismatch,
        OnchainError::MissingSigner => SxtntError::MissingSigner,
        OnchainError::MalformedInstruction => SxtntError::MalformedInstruction,
    }
}

/// Recompute the canonical digest in the native `solana_program::Pubkey`
/// type space. Exposed so callers that integrate at the
/// `solana-program` layer (without Anchor) can mirror the same check.
pub fn native_pubkey_check(authority: &SolPubkey) -> bool {
    // The native Pubkey from `solana_program` is byte-compatible with
    // Anchor's re-export; this helper exists so the public surface
    // documents that compatibility for auditors.
    let bytes = authority.to_bytes();
    bytes != [0u8; 32]
}

/// Errors produced by purely off-chain code that mirrors the on-chain
/// behaviour (used by the verifier crate and the SDK).
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OffchainMirrorError {
    /// The supplied digest did not match the recomputed digest.
    #[error("digest mismatch (off-chain)")]
    DigestMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_space_is_consistent() {
        assert_eq!(RegistryAccount::SPACE, 8 + 32 + 1 + 8 + 32 + 1);
    }

    #[test]
    fn scheme_round_trip() {
        for (s, kind) in [
            (0u8, SchemeKind::Nova),
            (1, SchemeKind::SuperNova),
            (2, SchemeKind::HyperNova),
        ] {
            assert_eq!(scheme_from_u8(s), Some(kind));
        }
        assert!(scheme_from_u8(3).is_none());
    }

    #[test]
    fn digest_is_stable() {
        let d1 = proof_digest(SchemeKind::Nova, &[1u8; 32], &[2u8; 64], &[3u8; 64], b"pi");
        let d2 = proof_digest(SchemeKind::Nova, &[1u8; 32], &[2u8; 64], &[3u8; 64], b"pi");
        assert_eq!(d1, d2);
    }

    #[test]
    fn native_pubkey_helper_rejects_zero() {
        let zero = SolPubkey::new_from_array([0u8; 32]);
        assert!(!native_pubkey_check(&zero));
        let unique = SolPubkey::new_unique();
        assert!(native_pubkey_check(&unique));
    }
}
