//! sxtnt-core
//!
//! Folding scheme primitives. This crate is a research-grade reference
//! implementation of the building blocks behind the SXTNT recursive ZK
//! coprocessor: relaxed-R1CS accumulators, Pedersen-style commitments,
//! and the IVC fold step shape described in the Nova family of papers
//! (Nova / SuperNova / HyperNova).
//!
//! The implementation deliberately stays compact and readable. It uses
//! the arkworks ecosystem (`ark-bn254`, `ark-ff`, `ark-relations`,
//! `ark-r1cs-std`) for the field/curve arithmetic, `halo2_proofs`'s
//! field traits for cross-checking the constraint shape, and `blake3`
//! for the Fiat-Shamir transcript and commitment binding.
//!
//! This crate is not a production verifier. It is the canonical
//! reference the rest of the workspace (`verifier`, `onchain`, `sdk`)
//! checks itself against, and is the artifact the public site
//! `https://sxtnt.fun` describes.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod accumulator;
pub mod commitment;
pub mod fold;
pub mod scheme;

use thiserror::Error;

/// The error type returned by every public entry point in this crate.
#[derive(Debug, Error)]
pub enum CoreError {
    /// A folded instance was rejected because the relaxed-R1CS check
    /// `Az * Bz - u * Cz = E` did not hold for the supplied witness.
    #[error("relaxed-R1CS satisfaction failed at row {0}")]
    RelaxedR1csViolated(usize),
    /// A commitment opening did not match the claimed digest.
    #[error("commitment opening mismatch")]
    OpeningMismatch,
    /// A transcript squeeze was called without a matching absorb.
    #[error("transcript state was empty when squeeze was requested")]
    EmptyTranscript,
    /// Domain separation tag was malformed (must be 0..=255 bytes).
    #[error("invalid domain separation tag length: {0}")]
    InvalidDomainTag(usize),
    /// A polynomial was supplied with a degree higher than the
    /// commitment scheme allows.
    #[error("polynomial degree {got} exceeds commitment capacity {max}")]
    PolyTooLarge {
        /// Degree of the polynomial supplied by the caller.
        got: usize,
        /// Maximum degree the commitment scheme is parameterised for.
        max: usize,
    },
}

/// The scalar field used throughout this reference implementation.
pub type Scalar = ark_bn254::Fr;

/// The pairing-friendly curve we build commitments on.
pub type Curve = ark_bn254::G1Affine;

/// Domain separation prefix for the Fiat-Shamir transcript. Every
/// absorb in the verifier and the prover prepends this label so that
/// transcripts produced by different protocols can never be confused.
pub const TRANSCRIPT_DOMAIN: &[u8] = b"sxtnt.fold.v1";

/// Build a domain-separated blake3 hasher seeded with the protocol
/// label and a caller-supplied subdomain (e.g. `b"accumulator"` or
/// `b"commitment"`). Returns a fresh hasher ready to absorb data.
pub fn domain_hasher(subdomain: &[u8]) -> Result<blake3::Hasher, CoreError> {
    if subdomain.len() > 255 {
        return Err(CoreError::InvalidDomainTag(subdomain.len()));
    }
    let mut h = blake3::Hasher::new();
    h.update(TRANSCRIPT_DOMAIN);
    h.update(&[subdomain.len() as u8]);
    h.update(subdomain);
    Ok(h)
}

/// Convert an arkworks scalar into a stable little-endian byte vector
/// suitable for absorbing into the Fiat-Shamir transcript or hashing
/// into a Pedersen commitment.
pub fn scalar_to_bytes(s: &Scalar) -> Vec<u8> {
    use ark_serialize::CanonicalSerialize;
    let mut buf = Vec::with_capacity(32);
    s.serialize_compressed(&mut buf)
        .expect("bn254 scalar serialises into a fixed-size buffer");
    buf
}

/// Convert a 32-byte slice back into a scalar. Returns `None` when the
/// bytes do not encode a canonical field element (i.e. the value is
/// >= the field modulus).
pub fn scalar_from_bytes(bytes: &[u8]) -> Option<Scalar> {
    use ark_serialize::CanonicalDeserialize;
    Scalar::deserialize_compressed(bytes).ok()
}

/// Cross-check: the relaxed-R1CS row `i` is satisfied iff
/// `A[i]·z * B[i]·z = u * C[i]·z + E[i]`. This helper materialises
/// the check for a single row and is used both by the accumulator
/// merge step and by the test suite.
pub fn check_relaxed_row(
    az: &Scalar,
    bz: &Scalar,
    cz: &Scalar,
    u: &Scalar,
    e: &Scalar,
) -> bool {
    let lhs = *az * *bz;
    let rhs = (*u) * (*cz) + *e;
    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, UniformRand};

    #[test]
    fn relaxed_row_holds_for_trivial_witness() {
        let one = Scalar::one();
        assert!(check_relaxed_row(&one, &one, &one, &one, &Scalar::from(0u64)));
    }

    #[test]
    fn domain_hasher_is_stable() {
        let a = domain_hasher(b"accumulator").unwrap().finalize();
        let b = domain_hasher(b"accumulator").unwrap().finalize();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn scalar_round_trip() {
        let mut rng = ark_std::test_rng();
        for _ in 0..16 {
            let s = Scalar::rand(&mut rng);
            let b = scalar_to_bytes(&s);
            assert_eq!(scalar_from_bytes(&b).unwrap(), s);
        }
    }
}
// blake3 keeps this cheap even on the BPF target.
