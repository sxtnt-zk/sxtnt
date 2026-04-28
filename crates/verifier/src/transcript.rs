//! Fiat-Shamir transcript over blake3.
//!
//! The transcript is a one-way state machine. Callers absorb labelled
//! byte slices in order, then squeeze challenges. Squeezing mixes the
//! current state forward so callers never accidentally squeeze the
//! same challenge twice.
//!
//! ```text
//!   state_0 = blake3("sxtnt.transcript.v1" || external_seed)
//!   absorb(label, msg):
//!       state := blake3(state || len(label) || label || len(msg) || msg)
//!   squeeze(label, n_bytes):
//!       out = blake3(state || "sq" || label || n_bytes_le)
//!       state := blake3(state || "advance" || out)
//!       return out[..n_bytes]
//! ```
//!
//! The labels are mandatory and bound into the state; that prevents
//! the classic Fiat-Shamir mistake where the prover skips an absorb
//! and the verifier doesn't notice.

use blake3::Hasher;
use sxtnt_core::{scalar_from_bytes, scalar_to_bytes, CoreError, Scalar};

const TRANSCRIPT_ROOT: &[u8] = b"sxtnt.transcript.v1";

/// A Fiat-Shamir transcript bound to the SXTNT domain.
#[derive(Clone, Debug)]
pub struct Transcript {
    state: [u8; 32],
    absorbs: u64,
    squeezes: u64,
}

impl Transcript {
    /// Build a fresh transcript with the supplied external seed.
    /// Two transcripts with the same seed and the same absorb sequence
    /// will produce the same squeeze sequence.
    pub fn new(seed: &[u8]) -> Self {
        let mut h = Hasher::new();
        h.update(TRANSCRIPT_ROOT);
        h.update(&(seed.len() as u64).to_le_bytes());
        h.update(seed);
        let mut state = [0u8; 32];
        state.copy_from_slice(h.finalize().as_bytes());
        Self {
            state,
            absorbs: 0,
            squeezes: 0,
        }
    }

    /// Absorb a labelled message.
    pub fn absorb(&mut self, label: &[u8], msg: &[u8]) {
        let mut h = Hasher::new();
        h.update(&self.state);
        h.update(&(label.len() as u64).to_le_bytes());
        h.update(label);
        h.update(&(msg.len() as u64).to_le_bytes());
        h.update(msg);
        self.state.copy_from_slice(h.finalize().as_bytes());
        self.absorbs = self.absorbs.saturating_add(1);
    }

    /// Absorb a bn254 scalar.
    pub fn absorb_scalar(&mut self, label: &[u8], s: &Scalar) {
        self.absorb(label, &scalar_to_bytes(s));
    }

    /// Squeeze a 32-byte challenge and advance the state.
    pub fn squeeze(&mut self, label: &[u8]) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(&self.state);
        h.update(b"sq");
        h.update(&(label.len() as u64).to_le_bytes());
        h.update(label);
        let out = h.finalize();
        let mut out_bytes = [0u8; 32];
        out_bytes.copy_from_slice(out.as_bytes());

        let mut h2 = Hasher::new();
        h2.update(&self.state);
        h2.update(b"advance");
        h2.update(&out_bytes);
        self.state.copy_from_slice(h2.finalize().as_bytes());
        self.squeezes = self.squeezes.saturating_add(1);
        out_bytes
    }

    /// Squeeze a challenge and reduce it into a bn254 scalar.
    /// Returns `EmptyTranscript` if the transcript has never been
    /// absorbed into — that is almost always a programming error.
    pub fn squeeze_scalar(&mut self, label: &[u8]) -> Result<Scalar, CoreError> {
        if self.absorbs == 0 {
            return Err(CoreError::EmptyTranscript);
        }
        let mut bytes = self.squeeze(label);
        // Clear the top two bits to land inside the bn254 scalar
        // field with overwhelming probability.
        bytes[31] &= 0x3f;
        use ark_ff::PrimeField;
        Ok(scalar_from_bytes(&bytes).unwrap_or_else(|| Scalar::from_le_bytes_mod_order(&bytes)))
    }

    /// Number of absorbs that have occurred. Useful for assertions.
    pub fn absorbs(&self) -> u64 {
        self.absorbs
    }

    /// Number of squeezes that have occurred.
    pub fn squeezes(&self) -> u64 {
        self.squeezes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_squeeze() {
        let mut a = Transcript::new(b"seed");
        let mut b = Transcript::new(b"seed");
        a.absorb(b"step", b"hello");
        b.absorb(b"step", b"hello");
        assert_eq!(a.squeeze(b"chal"), b.squeeze(b"chal"));
    }

    #[test]
    fn different_label_different_challenge() {
        let mut t = Transcript::new(b"seed");
        t.absorb(b"step", b"hello");
        let c1 = t.clone().squeeze(b"chal-1");
        let c2 = t.squeeze(b"chal-2");
        assert_ne!(c1, c2);
    }

    #[test]
    fn empty_transcript_squeeze_errors() {
        let mut t = Transcript::new(b"seed");
        assert!(matches!(
            t.squeeze_scalar(b"too-early"),
            Err(CoreError::EmptyTranscript)
        ));
    }

    #[test]
    fn squeeze_advances_state() {
        let mut t = Transcript::new(b"seed");
        t.absorb(b"step", b"hello");
        let c1 = t.squeeze(b"chal");
        let c2 = t.squeeze(b"chal");
        assert_ne!(c1, c2);
    }
}
// note: stays in lockstep with the Rust side.
