//! Anchor program skeleton.
//!
//! This module declares the instruction set the SXTNT Solana program
//! exposes. The Anchor `#[program]` attribute generates the
//! dispatcher, the IDL, and the client bindings under `sdk/typescript`.
//!
//! The reference implementation focuses on three instructions:
//!
//! * `init_registry` — create a `ProofRegistry` PDA for an authority.
//! * `accept_proof` — verify a canonical proof digest and append it
//!   to the registry.
//! * `close_registry` — remove the registry and reclaim lamports.
//!
//! The full verifier circuit is out of scope for a single-file
//! reference; the production program ships a separate verifier crate
//! whose interface this module pins.

use anchor_lang::prelude::*;
use sxtnt_core::scheme::SchemeKind;

use crate::{proof_digest, OnchainError, PROOF_SEED, REGISTRY_SEED};

declare_id!("7n5uUZyKVEXfGwgEbVeEQXedqiEigbzKFV9bNDBv74TJ");

/// The Anchor program entry. Generated dispatcher binds these
/// instructions to the canonical Solana entrypoint.
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
        reg.scheme = scheme as u8;
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

/// On-chain registry state.
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

/// On-chain accepted-proof state.
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

fn scheme_from_u8(s: u8) -> Option<SchemeKind> {
    match s {
        0 => Some(SchemeKind::Nova),
        1 => Some(SchemeKind::SuperNova),
        2 => Some(SchemeKind::HyperNova),
        _ => None,
    }
}

/// Map an `OnchainError` to an Anchor error code so the program's
/// error surface is consistent with the off-chain reference.
pub fn map_err(err: OnchainError) -> SxtntError {
    match err {
        OnchainError::DigestMismatch | OnchainError::VerifierRejection => SxtntError::DigestMismatch,
        OnchainError::AlreadyInitialized => SxtntError::MalformedInstruction,
        OnchainError::SchemeMismatch => SxtntError::SchemeMismatch,
        OnchainError::MissingSigner => SxtntError::MissingSigner,
        OnchainError::MalformedInstruction => SxtntError::MalformedInstruction,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_space_is_consistent() {
        // Discriminator + fields. Sanity check the math.
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
}
// note: stays in lockstep with the Rust side.
