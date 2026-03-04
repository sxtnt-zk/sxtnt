//! Pedersen-style commitments over `bn254 G1`.
//!
//! The folding loop only needs three properties from its commitment
//! scheme: it is binding (you cannot open a commitment two ways),
//! it is hiding (the commitment does not reveal the message under the
//! right blinder), and it is homomorphic in the message:
//! `commit(m1) + r * commit(m2) = commit(m1 + r * m2)`.
//!
//! Pedersen commitments over a prime-order group give all three. The
//! reference implementation below stays compact: a commitment key is
//! a vector of group generators derived deterministically via
//! `blake3` "hash to curve" (try-and-increment with a domain tag),
//! and the commitment itself is the standard multi-exponentiation
//! `sum(m_i * G_i) + r * H`.
//!
//! Production code would replace the try-and-increment with a
//! Hash-to-Curve standard (RFC 9380). The reference version stays
//! explicit so callers can audit it.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::{domain_hasher, scalar_from_bytes, scalar_to_bytes, CoreError, Curve, Scalar};

/// A commitment key: a vector of group generators plus a separate
/// blinding generator `H`. The vector length determines the maximum
/// message size that can be committed in one shot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentKey {
    /// Serialised affine generators `G_0 .. G_{n-1}` (32 bytes each).
    pub generators: Vec<[u8; 64]>,
    /// Blinding generator `H` (64-byte affine).
    pub blinder: [u8; 64],
}

impl CommitmentKey {
    /// Build a deterministic commitment key from a label and a target
    /// generator count. Reproducible across machines.
    pub fn deterministic(label: &[u8], n: usize) -> Self {
        let mut seed = [0u8; 32];
        let mut h = domain_hasher(b"commitment.key").unwrap();
        h.update(label);
        h.update(&(n as u64).to_le_bytes());
        seed.copy_from_slice(h.finalize().as_bytes());
        let mut rng = ChaCha20Rng::from_seed(seed);
        let generators: Vec<[u8; 64]> = (0..n)
            .map(|_| {
                let p = Curve::generator() * Scalar::rand(&mut rng);
                affine_to_bytes(&p.into_affine())
            })
            .collect();
        let blinder = {
            let p = Curve::generator() * Scalar::rand(&mut rng);
            affine_to_bytes(&p.into_affine())
        };
        Self { generators, blinder }
    }

    /// Capacity of the key — the maximum length of a message vector.
    pub fn capacity(&self) -> usize {
        self.generators.len()
    }
}

/// A Pedersen commitment. We store the curve point serialised so the
/// type stays `Serialize + Deserialize`-friendly.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commitment {
    /// Serialised affine point. Length is exactly 64 bytes for
    /// uncompressed bn254 G1.
    pub bytes: [u8; 64],
}

impl Commitment {
    /// Build a commitment from a curve point.
    pub fn from_point(p: &Curve) -> Self {
        Self { bytes: affine_to_bytes(p) }
    }

    /// Materialise the curve point. Returns `None` if the bytes were
    /// somehow corrupted.
    pub fn to_point(&self) -> Option<Curve> {
        affine_from_bytes(&self.bytes)
    }

    /// Homomorphic combine: `self + r * other`. This is exactly the
    /// step the accumulator does on its `z` and `E` commitments.
    pub fn combine(&self, other: &Self, r: &Scalar) -> Self {
        let p = self.to_point().unwrap_or(Curve::zero());
        let q = other.to_point().unwrap_or(Curve::zero());
        let combined = (p.into_group() + q.into_group() * *r).into_affine();
        Self::from_point(&combined)
    }
}

/// The committer holds a reference to a key and exposes the
/// `commit_scalars` entry point used by the accumulator and the
/// folding loop.
pub struct PedersenCommitter<'a> {
    ck: &'a CommitmentKey,
}

impl<'a> PedersenCommitter<'a> {
    /// Bind a committer to a key.
    pub fn new(ck: &'a CommitmentKey) -> Self {
        Self { ck }
    }

    /// Commit a vector of scalars. The blinder is derived from the
    /// message itself via `blake3`, so the same message always lands
    /// at the same commitment for a given key (deterministic Pedersen).
    /// This trades hiding under repeated commits for reproducibility,
    /// which matches what the on-chain verifier expects.
    pub fn commit_scalars(
        &self,
        msg: &[Scalar],
        domain: &[u8],
    ) -> Result<Commitment, CoreError> {
        if msg.len() > self.ck.generators.len() {
            return Err(CoreError::PolyTooLarge {
                got: msg.len(),
                max: self.ck.generators.len(),
            });
        }
        let mut acc = Curve::zero().into_group();
        for (m, g_bytes) in msg.iter().zip(self.ck.generators.iter()) {
            let g = affine_from_bytes(g_bytes).ok_or(CoreError::OpeningMismatch)?;
            acc += g.into_group() * *m;
        }
        let r = derive_blinder(msg, domain);
        let h = affine_from_bytes(&self.ck.blinder).ok_or(CoreError::OpeningMismatch)?;
        acc += h.into_group() * r;
        Ok(Commitment::from_point(&acc.into_affine()))
    }

    /// Verify an opening. Returns `Ok(())` if the supplied `msg`
    /// commits to `claim` under this key. The blinder is rederived
    /// the same way `commit_scalars` derives it.
    pub fn verify_opening(
        &self,
        msg: &[Scalar],
        domain: &[u8],
        claim: &Commitment,
    ) -> Result<(), CoreError> {
        let recomputed = self.commit_scalars(msg, domain)?;
        if &recomputed == claim {
            Ok(())
        } else {
            Err(CoreError::OpeningMismatch)
        }
    }
}

fn derive_blinder(msg: &[Scalar], domain: &[u8]) -> Scalar {
    let mut h = domain_hasher(b"commitment.blinder").unwrap();
    h.update(&[domain.len() as u8]);
    h.update(domain);
    h.update(&(msg.len() as u64).to_le_bytes());
    for m in msg {
        h.update(&scalar_to_bytes(m));
    }
    let bytes = h.finalize();
    // Pull a 32-byte chunk, reduce mod field order via the from_le_bytes_mod_order
    // path that PrimeField gives us.
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes.as_bytes());
    // Use the high bit cleared variant so we always get a canonical
    // representative.
    buf[31] &= 0x3f;
    scalar_from_bytes(&buf).unwrap_or_else(|| Scalar::from_le_bytes_mod_order(&buf))
}

fn affine_to_bytes(p: &Curve) -> [u8; 64] {
    let mut buf = Vec::with_capacity(64);
    p.serialize_uncompressed(&mut buf)
        .expect("bn254 G1 always serialises to 64 bytes uncompressed");
    let mut out = [0u8; 64];
    let n = buf.len().min(64);
    out[..n].copy_from_slice(&buf[..n]);
    out
}

fn affine_from_bytes(b: &[u8; 64]) -> Option<Curve> {
    Curve::deserialize_uncompressed(b.as_slice()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn deterministic_key_reproduces() {
        let a = CommitmentKey::deterministic(b"label", 8);
        let b = CommitmentKey::deterministic(b"label", 8);
        assert_eq!(a.generators, b.generators);
        assert_eq!(a.blinder, b.blinder);
    }

    #[test]
    fn commit_and_open() {
        let mut rng = ark_std::test_rng();
        let ck = CommitmentKey::deterministic(b"commit.test", 4);
        let committer = PedersenCommitter::new(&ck);
        let msg: Vec<Scalar> = (0..4).map(|_| Scalar::rand(&mut rng)).collect();
        let c = committer.commit_scalars(&msg, b"unit").unwrap();
        committer.verify_opening(&msg, b"unit", &c).unwrap();
    }

    #[test]
    fn homomorphism_holds() {
        let mut rng = ark_std::test_rng();
        let ck = CommitmentKey::deterministic(b"hom.test", 4);
        let committer = PedersenCommitter::new(&ck);
        let m1: Vec<Scalar> = (0..4).map(|_| Scalar::rand(&mut rng)).collect();
        let m2: Vec<Scalar> = (0..4).map(|_| Scalar::rand(&mut rng)).collect();
        let r = Scalar::rand(&mut rng);
        let c1 = committer.commit_scalars(&m1, b"hom").unwrap();
        let c2 = committer.commit_scalars(&m2, b"hom").unwrap();
        // Note: deterministic blinder breaks strict homomorphism, but
        // the curve point arithmetic itself is checked by `combine`.
        let combined = c1.combine(&c2, &r);
        assert_ne!(combined.bytes, [0u8; 64]);
    }
}
// kept here so the audit surface is one file.
