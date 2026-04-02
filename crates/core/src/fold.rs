//! The IVC fold step.
//!
//! Folding compresses two relaxed-R1CS instances into one by taking
//! a random linear combination governed by a single Fiat-Shamir
//! challenge `r`. The shape of the step is:
//!
//! ```text
//!   acc'   =  acc  +  r * fresh
//!   step  +=  1
//! ```
//!
//! where the addition runs over the per-row witness triples
//! `(Az, Bz, Cz)`, the error vector `E`, the slack scalar `u`, and the
//! commitments to `z` and `E`. The challenge `r` is squeezed from a
//! transcript that has absorbed both accumulators and the public
//! inputs — that ties the prover to a binding commitment.
//!
//! This module orchestrates the step. The actual arithmetic lives in
//! `Accumulator::merge`; here we add the transcript wiring and a
//! `prove_step` / `verify_step` pair that the higher-level
//! `scheme.rs` API drives.

use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::accumulator::Accumulator;
use crate::commitment::CommitmentKey;
use crate::{domain_hasher, scalar_from_bytes, scalar_to_bytes, CoreError, Scalar};

/// One step of the folding loop, as it appears in a transcript.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FoldStep {
    /// The challenge that was used to fold this step. Recorded so
    /// the verifier can replay the same transcript.
    pub challenge: [u8; 32],
    /// Step index. Matches `acc.step` after the step is applied.
    pub index: u64,
}

/// Prover-side fold. Squeezes a Fiat-Shamir challenge from `acc`,
/// `fresh`, and the supplied public input, then calls
/// `Accumulator::merge`. Returns the new accumulator and the
/// transcript record.
pub fn prove_step(
    acc: &Accumulator,
    fresh: &Accumulator,
    public_input: &[Scalar],
) -> Result<(Accumulator, FoldStep), CoreError> {
    let challenge = squeeze_challenge(acc, fresh, public_input)?;
    let merged = acc.merge(fresh, &challenge)?;
    let step = FoldStep {
        challenge: into_array(scalar_to_bytes(&challenge)),
        index: merged.step,
    };
    Ok((merged, step))
}

/// Verifier-side fold. Recomputes the challenge from the same
/// transcript, checks the recorded challenge matches, and then asks
/// the merged accumulator to satisfy the relaxed-R1CS check.
pub fn verify_step(
    acc: &Accumulator,
    fresh: &Accumulator,
    public_input: &[Scalar],
    proof: &FoldStep,
    merged: &Accumulator,
) -> Result<(), CoreError> {
    let challenge = squeeze_challenge(acc, fresh, public_input)?;
    let claimed = scalar_from_bytes(&proof.challenge)
        .ok_or(CoreError::RelaxedR1csViolated(0))?;
    if claimed != challenge {
        return Err(CoreError::OpeningMismatch);
    }
    let replay = acc.merge(fresh, &challenge)?;
    // Check that the prover's merged accumulator agrees with our
    // independent replay on the visible parts (u, commitments, step).
    if replay.u != merged.u
        || replay.commitment_z != merged.commitment_z
        || replay.commitment_e != merged.commitment_e
        || replay.step != merged.step
    {
        return Err(CoreError::OpeningMismatch);
    }
    merged.check()
}

/// Run a full folding chain over `instances`, starting from a fresh
/// accumulator seeded with the first instance. Returns the final
/// accumulator and the list of fold steps. This is the canonical
/// reference IVC loop.
pub fn fold_chain(
    ck: &CommitmentKey,
    instances: &[Accumulator],
    public_input: &[Scalar],
) -> Result<(Accumulator, Vec<FoldStep>), CoreError> {
    let _ = ck; // commitment key only used by the caller-side fresh ctor
    if instances.is_empty() {
        return Err(CoreError::RelaxedR1csViolated(0));
    }
    let mut acc = instances[0].clone();
    let mut steps = Vec::with_capacity(instances.len().saturating_sub(1));
    for fresh in &instances[1..] {
        let (next, step) = prove_step(&acc, fresh, public_input)?;
        acc = next;
        steps.push(step);
    }
    Ok((acc, steps))
}

fn squeeze_challenge(
    acc: &Accumulator,
    fresh: &Accumulator,
    public_input: &[Scalar],
) -> Result<Scalar, CoreError> {
    let mut h = domain_hasher(b"fold.challenge")?;
    h.update(&acc.u);
    h.update(&acc.commitment_z.bytes);
    h.update(&acc.commitment_e.bytes);
    h.update(&fresh.u);
    h.update(&fresh.commitment_z.bytes);
    h.update(&fresh.commitment_e.bytes);
    h.update(&(public_input.len() as u64).to_le_bytes());
    for p in public_input {
        h.update(&scalar_to_bytes(p));
    }
    h.update(&acc.step.to_le_bytes());
    let bytes = h.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes.as_bytes());
    // Clear the top two bits so the result lies inside the bn254
    // scalar field with overwhelming probability after reduction.
    buf[31] &= 0x3f;
    Ok(scalar_from_bytes(&buf).unwrap_or_else(|| Scalar::from_le_bytes_mod_order(&buf)))
}

fn into_array(v: Vec<u8>) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = v.len().min(32);
    out[..n].copy_from_slice(&v[..n]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::{Accumulator, RelaxedRow};
    use crate::commitment::CommitmentKey;
    use ark_ff::UniformRand;

    fn row(rng: &mut impl rand::Rng) -> RelaxedRow {
        let az = Scalar::rand(rng);
        let bz = Scalar::rand(rng);
        let cz = az * bz;
        RelaxedRow::from_scalars(&az, &bz, &cz, &Scalar::from(0u64))
    }

    #[test]
    fn challenge_is_deterministic() {
        let mut rng = ark_std::test_rng();
        let ck = CommitmentKey::deterministic(b"fold.test", 4);
        let rows: Vec<_> = (0..4).map(|_| row(&mut rng)).collect();
        let z: Vec<_> = (0..4).map(|_| Scalar::rand(&mut rng)).collect();
        let a = Accumulator::fresh(&ck, rows.clone(), &z).unwrap();
        let b = Accumulator::fresh(&ck, rows, &z).unwrap();
        let pi = vec![Scalar::from(7u64)];
        let c1 = squeeze_challenge(&a, &b, &pi).unwrap();
        let c2 = squeeze_challenge(&a, &b, &pi).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn prove_and_verify_one_step() {
        let mut rng = ark_std::test_rng();
        let ck = CommitmentKey::deterministic(b"fold.test", 4);
        let rows_a: Vec<_> = (0..4).map(|_| row(&mut rng)).collect();
        let rows_b: Vec<_> = (0..4).map(|_| row(&mut rng)).collect();
        let z: Vec<_> = (0..4).map(|_| Scalar::rand(&mut rng)).collect();
        let a = Accumulator::fresh(&ck, rows_a, &z).unwrap();
        let b = Accumulator::fresh(&ck, rows_b, &z).unwrap();
        let pi = vec![Scalar::from(11u64), Scalar::from(13u64)];
        let (merged, step) = prove_step(&a, &b, &pi).unwrap();
        verify_step(&a, &b, &pi, &step, &merged).unwrap();
        assert_eq!(step.index, 1);
    }
}
// transcript domain tag is included one level up.
