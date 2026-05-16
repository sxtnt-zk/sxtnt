//! Relaxed-R1CS accumulator (Nova-flavoured).
//!
//! In a vanilla R1CS instance each row `i` of the constraint system
//! must satisfy `A[i]·z * B[i]·z = C[i]·z`. The Nova family relaxes
//! this to `A[i]·z * B[i]·z = u * C[i]·z + E[i]` where `u` is a scalar
//! and `E` is the "error" vector. The relaxed form is closed under
//! random linear combination, which is what makes folding possible.
//!
//! This module implements the accumulator carried by the folding loop:
//! it stores the running `(u, E, z)` plus the commitments to `z` and
//! `E`, exposes a `merge` step that absorbs one fresh instance, and
//! provides a satisfaction check used by the test suite and by the
//! `verifier` crate.

use ark_ff::{One, Zero};
use serde::{Deserialize, Serialize};

use crate::commitment::{Commitment, CommitmentKey, PedersenCommitter};
use crate::{check_relaxed_row, scalar_from_bytes, scalar_to_bytes, CoreError, Scalar};

/// A single relaxed-R1CS row, materialised. Production folding stores
/// witnesses sparsely; the reference implementation keeps the
/// per-row triple explicit for clarity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelaxedRow {
    /// `A[i]·z`
    pub az: [u8; 32],
    /// `B[i]·z`
    pub bz: [u8; 32],
    /// `C[i]·z`
    pub cz: [u8; 32],
    /// Error term for this row.
    pub e: [u8; 32],
}

impl RelaxedRow {
    /// Construct a row from raw arkworks scalars.
    pub fn from_scalars(az: &Scalar, bz: &Scalar, cz: &Scalar, e: &Scalar) -> Self {
        Self {
            az: to_array(scalar_to_bytes(az)),
            bz: to_array(scalar_to_bytes(bz)),
            cz: to_array(scalar_to_bytes(cz)),
            e: to_array(scalar_to_bytes(e)),
        }
    }

    /// Materialise the row's scalars. Returns `None` if any byte
    /// triple does not encode a canonical field element.
    pub fn to_scalars(&self) -> Option<(Scalar, Scalar, Scalar, Scalar)> {
        Some((
            scalar_from_bytes(&self.az)?,
            scalar_from_bytes(&self.bz)?,
            scalar_from_bytes(&self.cz)?,
            scalar_from_bytes(&self.e)?,
        ))
    }
}

/// The full accumulator state. The folding loop returns a new
/// `Accumulator` after each step; the previous one is discarded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Accumulator {
    /// Scalar slack `u`. Starts at one for a fresh instance and stays
    /// in the field after every merge.
    pub u: [u8; 32],
    /// Commitment to the witness vector `z`.
    pub commitment_z: Commitment,
    /// Commitment to the error vector `E`.
    pub commitment_e: Commitment,
    /// Materialised relaxed rows. Stored so the test suite and the
    /// `verifier` crate can replay the satisfaction check.
    pub rows: Vec<RelaxedRow>,
    /// Step counter — how many times this accumulator has been
    /// merged. Useful for debugging and for the Fiat-Shamir
    /// transcript label.
    pub step: u64,
}

impl Accumulator {
    /// Build a fresh accumulator from a single satisfied R1CS instance.
    /// `u` is set to one, `E` is the zero vector and the commitments
    /// open to the supplied `(z, 0)`.
    pub fn fresh(
        ck: &CommitmentKey,
        rows: Vec<RelaxedRow>,
        z: &[Scalar],
    ) -> Result<Self, CoreError> {
        let committer = PedersenCommitter::new(ck);
        let commitment_z = committer.commit_scalars(z, b"acc.z")?;
        let zeros: Vec<Scalar> = (0..rows.len()).map(|_| Scalar::zero()).collect();
        let commitment_e = committer.commit_scalars(&zeros, b"acc.e")?;
        Ok(Self {
            u: to_array(scalar_to_bytes(&Scalar::one())),
            commitment_z,
            commitment_e,
            rows,
            step: 0,
        })
    }

    /// Return `u` as an arkworks scalar.
    pub fn u_scalar(&self) -> Option<Scalar> {
        scalar_from_bytes(&self.u)
    }

    /// Verify the relaxed-R1CS check for every stored row. Returns
    /// `Ok(())` if every row satisfies `Az*Bz = u*Cz + E`, otherwise
    /// the first violating row index.
    pub fn check(&self) -> Result<(), CoreError> {
        let u = self.u_scalar().ok_or(CoreError::RelaxedR1csViolated(0))?;
        for (i, row) in self.rows.iter().enumerate() {
            let (az, bz, cz, e) = row
                .to_scalars()
                .ok_or(CoreError::RelaxedR1csViolated(i))?;
            if !check_relaxed_row(&az, &bz, &cz, &u, &e) {
                return Err(CoreError::RelaxedR1csViolated(i));
            }
        }
        Ok(())
    }

    /// Merge another accumulator into this one using folding challenge
    /// `r`. Both accumulators must agree on the row count.
    ///
    /// The merge produces a new accumulator with:
    /// * `u' = u_self + r * u_other`
    /// * `row_i' = self.row_i + r * other.row_i` (component-wise)
    ///
    /// The error term picks up the cross-product correction
    /// `r * (A_self·z_other * B_other·z_self + A_other·z_self * B_self·z_other - u_self * C_other - u_other * C_self)`
    /// which is exactly what keeps the relaxed-R1CS check closed.
    pub fn merge(&self, other: &Self, r: &Scalar) -> Result<Self, CoreError> {
        if self.rows.len() != other.rows.len() {
            return Err(CoreError::RelaxedR1csViolated(self.rows.len()));
        }
        let u_self = self.u_scalar().ok_or(CoreError::RelaxedR1csViolated(0))?;
        let u_other = other
            .u_scalar()
            .ok_or(CoreError::RelaxedR1csViolated(0))?;
        let u_new = u_self + *r * u_other;

        let mut new_rows = Vec::with_capacity(self.rows.len());
        for (i, (a, b)) in self.rows.iter().zip(other.rows.iter()).enumerate() {
            let (az_a, bz_a, cz_a, e_a) =
                a.to_scalars().ok_or(CoreError::RelaxedR1csViolated(i))?;
            let (az_b, bz_b, cz_b, e_b) =
                b.to_scalars().ok_or(CoreError::RelaxedR1csViolated(i))?;
            let az_new = az_a + *r * az_b;
            let bz_new = bz_a + *r * bz_b;
            let cz_new = cz_a + *r * cz_b;
            let cross = az_a * bz_b + az_b * bz_a - u_self * cz_b - u_other * cz_a;
            let e_new = e_a + *r * e_b + *r * cross;
            new_rows.push(RelaxedRow::from_scalars(&az_new, &bz_new, &cz_new, &e_new));
        }

        Ok(Self {
            u: to_array(scalar_to_bytes(&u_new)),
            commitment_z: self.commitment_z.combine(&other.commitment_z, r),
            commitment_e: self.commitment_e.combine(&other.commitment_e, r),
            rows: new_rows,
            step: self.step.saturating_add(1),
        })
    }
}

fn to_array(v: Vec<u8>) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = v.len().min(32);
    out[..n].copy_from_slice(&v[..n]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::CommitmentKey;
    use ark_ff::UniformRand;

    fn satisfied_row(rng: &mut impl rand::Rng) -> RelaxedRow {
        // construct a satisfied row by picking az, bz freely and
        // setting cz = az*bz so the relaxed-R1CS check with u=1, e=0
        // holds.
        let az = Scalar::rand(rng);
        let bz = Scalar::rand(rng);
        let cz = az * bz;
        let e = Scalar::from(0u64);
        RelaxedRow::from_scalars(&az, &bz, &cz, &e)
    }

    #[test]
    fn fresh_accumulator_checks_clean() {
        let mut rng = ark_std::test_rng();
        let rows = (0..8).map(|_| satisfied_row(&mut rng)).collect::<Vec<_>>();
        let z = (0..8).map(|_| Scalar::rand(&mut rng)).collect::<Vec<_>>();
        let ck = CommitmentKey::deterministic(b"test.ck", 8);
        let acc = Accumulator::fresh(&ck, rows, &z).unwrap();
        acc.check().unwrap();
        assert_eq!(acc.step, 0);
    }

    #[test]
    fn merge_advances_step() {
        let mut rng = ark_std::test_rng();
        let rows_a = (0..4).map(|_| satisfied_row(&mut rng)).collect::<Vec<_>>();
        let rows_b = (0..4).map(|_| satisfied_row(&mut rng)).collect::<Vec<_>>();
        let z = (0..4).map(|_| Scalar::rand(&mut rng)).collect::<Vec<_>>();
        let ck = CommitmentKey::deterministic(b"test.ck", 4);
        let a = Accumulator::fresh(&ck, rows_a, &z).unwrap();
        let b = Accumulator::fresh(&ck, rows_b, &z).unwrap();
        let merged = a.merge(&b, &Scalar::rand(&mut rng)).unwrap();
        assert_eq!(merged.step, 1);
        assert_eq!(merged.rows.len(), 4);
    }
}
// note: stays in lockstep with the Rust side.
