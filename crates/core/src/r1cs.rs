//! Arkworks R1CS bridge.
//!
//! The accumulator in [`crate::accumulator`] stores relaxed-R1CS rows
//! as raw 32-byte scalars. The folding loop only needs that compact
//! representation, but auditors who read the README expect to see the
//! standard `ark-relations` / `ark-r1cs-std` interfaces wired up to
//! actual rows.
//!
//! This module is the bridge. Given a slice of [`RelaxedRow`]s and a
//! witness vector, it materialises an `ark_relations::r1cs::ConstraintSystem`
//! that asserts `az * bz = u * cz + e` for every row, then calls
//! `cs.is_satisfied()`. The same `RelaxedRow` that the accumulator
//! merges is the input.
//!
//! The constraint system is built with `FpVar` witness variables from
//! `ark_r1cs_std`, so the cross-check exercises the full arkworks
//! R1CS stack a Halo2 / Nova-style prover would lower into.

use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};

use crate::accumulator::RelaxedRow;
use crate::{CoreError, Scalar};

/// Build a constraint system that materialises every row in `rows`
/// and asserts the relaxed-R1CS predicate for it. Returns the live
/// `ConstraintSystemRef` so a caller can inspect the witness or call
/// `is_satisfied()` separately.
pub fn build_relaxed_cs(
    rows: &[RelaxedRow],
    u: &Scalar,
) -> Result<ConstraintSystemRef<Scalar>, CoreError> {
    let cs = ConstraintSystem::<Scalar>::new_ref();
    let u_var = FpVar::<Scalar>::new_witness(cs.clone(), || Ok(*u))
        .map_err(synth_err)?;
    for (i, row) in rows.iter().enumerate() {
        let (az, bz, cz, e) = row
            .to_scalars()
            .ok_or(CoreError::RelaxedR1csViolated(i))?;
        let az_var = FpVar::new_witness(cs.clone(), || Ok(az)).map_err(synth_err)?;
        let bz_var = FpVar::new_witness(cs.clone(), || Ok(bz)).map_err(synth_err)?;
        let cz_var = FpVar::new_witness(cs.clone(), || Ok(cz)).map_err(synth_err)?;
        let e_var = FpVar::new_witness(cs.clone(), || Ok(e)).map_err(synth_err)?;
        // The relaxed-R1CS predicate: az * bz == u * cz + e.
        let lhs = az_var * bz_var;
        let rhs = (&u_var * cz_var) + e_var;
        lhs.enforce_equal(&rhs).map_err(synth_err)?;
    }
    Ok(cs)
}

/// Verify every relaxed-R1CS row through the arkworks constraint
/// system. Returns the index of the first violating row if the
/// predicate is not satisfied.
pub fn verify_relaxed_via_cs(rows: &[RelaxedRow], u: &Scalar) -> Result<(), CoreError> {
    let cs = build_relaxed_cs(rows, u)?;
    if cs.is_satisfied().map_err(synth_err)? {
        Ok(())
    } else {
        // Walk the rows so we can return the first one that fails the
        // explicit predicate. The constraint system itself only knows
        // "some constraint failed".
        for (i, row) in rows.iter().enumerate() {
            let (az, bz, cz, e) = row
                .to_scalars()
                .ok_or(CoreError::RelaxedR1csViolated(i))?;
            if !crate::check_relaxed_row(&az, &bz, &cz, u, &e) {
                return Err(CoreError::RelaxedR1csViolated(i));
            }
        }
        Err(CoreError::RelaxedR1csViolated(rows.len()))
    }
}

/// Report how many constraints the relaxed-R1CS system uses for a
/// given row vector. One constraint per row in the reference shape.
pub fn constraint_count(rows: &[RelaxedRow], u: &Scalar) -> Result<usize, CoreError> {
    let cs = build_relaxed_cs(rows, u)?;
    cs.finalize();
    Ok(cs.num_constraints())
}

fn synth_err(_: SynthesisError) -> CoreError {
    CoreError::RelaxedR1csViolated(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, UniformRand, Zero};

    fn satisfied_row(rng: &mut impl rand::Rng) -> RelaxedRow {
        let az = Scalar::rand(rng);
        let bz = Scalar::rand(rng);
        let cz = az * bz;
        RelaxedRow::from_scalars(&az, &bz, &cz, &Scalar::zero())
    }

    #[test]
    fn empty_system_is_satisfied() {
        let rows: Vec<RelaxedRow> = vec![];
        verify_relaxed_via_cs(&rows, &Scalar::one()).expect("empty system is trivially OK");
    }

    #[test]
    fn satisfied_rows_pass() {
        let mut rng = ark_std::test_rng();
        let rows: Vec<RelaxedRow> = (0..6).map(|_| satisfied_row(&mut rng)).collect();
        verify_relaxed_via_cs(&rows, &Scalar::one()).unwrap();
    }

    #[test]
    fn unsatisfied_row_is_caught() {
        let mut rng = ark_std::test_rng();
        let bad = RelaxedRow::from_scalars(
            &Scalar::from(2u64),
            &Scalar::from(3u64),
            &Scalar::from(99u64), // wrong cz
            &Scalar::zero(),
        );
        let good = satisfied_row(&mut rng);
        let rows = vec![good, bad];
        let err = verify_relaxed_via_cs(&rows, &Scalar::one()).unwrap_err();
        match err {
            CoreError::RelaxedR1csViolated(i) => assert_eq!(i, 1),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn constraint_count_grows_with_rows() {
        let mut rng = ark_std::test_rng();
        let small: Vec<RelaxedRow> = (0..2).map(|_| satisfied_row(&mut rng)).collect();
        let large: Vec<RelaxedRow> = (0..6).map(|_| satisfied_row(&mut rng)).collect();
        let n_small = constraint_count(&small, &Scalar::one()).unwrap();
        let n_large = constraint_count(&large, &Scalar::one()).unwrap();
        assert!(n_large > n_small);
    }
}
