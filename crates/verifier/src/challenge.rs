//! Challenge derivation helpers.
//!
//! The folding loop derives three classes of challenge:
//!
//! * `fold` — the random linear combination scalar that merges two
//!   accumulators into one.
//! * `commit` — the blinder mixed into a Pedersen commitment.
//! * `selector` — for SuperNova, the per-step circuit index.
//!
//! Each of these is squeezed from a [`Transcript`] under a fixed
//! label. Routing every challenge through this module keeps the
//! domain tags consistent between prover and verifier.

use sxtnt_core::{CoreError, Scalar};

use crate::transcript::Transcript;

/// Labels used by the SXTNT folding loop. Constants so a typo
/// produces a compile error instead of a silent mismatch.
pub mod label {
    /// Random linear combination scalar.
    pub const FOLD: &[u8] = b"sxtnt.chal.fold";
    /// Pedersen blinding scalar.
    pub const COMMIT: &[u8] = b"sxtnt.chal.commit";
    /// SuperNova circuit selector.
    pub const SELECTOR: &[u8] = b"sxtnt.chal.selector";
    /// HyperNova lane index.
    pub const LANE: &[u8] = b"sxtnt.chal.lane";
}

/// A builder that wraps a transcript and exposes the four challenge
/// derivations the folding scheme uses. Keeping this layer thin makes
/// it easy to swap the underlying hash if needed.
pub struct ChallengeBuilder<'a> {
    transcript: &'a mut Transcript,
}

impl<'a> ChallengeBuilder<'a> {
    /// Bind a builder to an existing transcript.
    pub fn new(transcript: &'a mut Transcript) -> Self {
        Self { transcript }
    }

    /// Absorb an accumulator's identifying bytes so the next squeeze
    /// is bound to it. Callers pass the `u` slack, the two
    /// commitments, and the step count.
    pub fn absorb_accumulator(
        &mut self,
        u: &[u8; 32],
        commitment_z: &[u8; 64],
        commitment_e: &[u8; 64],
        step: u64,
    ) {
        self.transcript.absorb(b"acc.u", u);
        self.transcript.absorb(b"acc.cz", commitment_z);
        self.transcript.absorb(b"acc.ce", commitment_e);
        self.transcript.absorb(b"acc.step", &step.to_le_bytes());
    }

    /// Absorb an ordered vector of public inputs.
    pub fn absorb_public_input(&mut self, pi: &[Scalar]) {
        self.transcript
            .absorb(b"pi.len", &(pi.len() as u64).to_le_bytes());
        for p in pi {
            self.transcript.absorb_scalar(b"pi.item", p);
        }
    }

    /// Squeeze the fold challenge.
    pub fn fold_challenge(&mut self) -> Result<Scalar, CoreError> {
        self.transcript.squeeze_scalar(label::FOLD)
    }

    /// Squeeze a Pedersen blinder.
    pub fn commit_blinder(&mut self) -> Result<Scalar, CoreError> {
        self.transcript.squeeze_scalar(label::COMMIT)
    }

    /// Squeeze a SuperNova selector, reduced modulo the circuit count.
    pub fn selector(&mut self, n_circuits: u16) -> Result<u16, CoreError> {
        let bytes = self.transcript.squeeze(label::SELECTOR);
        let prefix = u16::from_le_bytes([bytes[0], bytes[1]]);
        Ok(if n_circuits == 0 { 0 } else { prefix % n_circuits })
    }

    /// Squeeze a HyperNova lane assignment.
    pub fn lane(&mut self, n_lanes: u8) -> Result<u8, CoreError> {
        let bytes = self.transcript.squeeze(label::LANE);
        Ok(if n_lanes == 0 { 0 } else { bytes[0] % n_lanes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_challenge_is_reproducible() {
        let mut a = Transcript::new(b"seed");
        let mut b = Transcript::new(b"seed");
        ChallengeBuilder::new(&mut a)
            .absorb_accumulator(&[1u8; 32], &[2u8; 64], &[3u8; 64], 0);
        ChallengeBuilder::new(&mut b)
            .absorb_accumulator(&[1u8; 32], &[2u8; 64], &[3u8; 64], 0);
        let c1 = ChallengeBuilder::new(&mut a).fold_challenge().unwrap();
        let c2 = ChallengeBuilder::new(&mut b).fold_challenge().unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn selector_lands_in_range() {
        let mut t = Transcript::new(b"seed");
        ChallengeBuilder::new(&mut t)
            .absorb_accumulator(&[1u8; 32], &[2u8; 64], &[3u8; 64], 0);
        let s = ChallengeBuilder::new(&mut t).selector(7).unwrap();
        assert!(s < 7);
    }

    #[test]
    fn lane_lands_in_range() {
        let mut t = Transcript::new(b"seed");
        ChallengeBuilder::new(&mut t)
            .absorb_accumulator(&[1u8; 32], &[2u8; 64], &[3u8; 64], 0);
        let l = ChallengeBuilder::new(&mut t).lane(4).unwrap();
        assert!(l < 4);
    }
}
// transcript domain tag is included one level up.
