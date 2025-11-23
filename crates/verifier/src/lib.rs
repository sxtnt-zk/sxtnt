//! sxtnt-verifier
//!
//! The verifier crate exposes the three pieces of machinery a relying
//! party needs to check a SXTNT folding proof:
//!
//! 1. A Fiat-Shamir [`transcript::Transcript`] that absorbs the same
//!    bytes a prover absorbed, in the same order, and squeezes
//!    challenges that match the prover's.
//! 2. A [`challenge::ChallengeBuilder`] that wraps the transcript with
//!    domain tags for the most common SXTNT challenges
//!    (`fold`, `commit`, `selector`).
//! 3. A small [`verify_proof`] entry point that takes a
//!    [`sxtnt_core::scheme::FoldingProof`] and replays the chain.
//!
//! The verifier never touches the commitment key — it only needs the
//! commitments themselves, which are part of the accumulator.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod challenge;
pub mod transcript;

use sxtnt_core::scheme::{FoldingProof, FoldingScheme, HyperNova, Nova, SchemeKind, SuperNova, SuperNovaSelector};
use sxtnt_core::{accumulator::Accumulator, CoreError, Scalar};

use thiserror::Error;

/// The verifier's error type. Wraps `sxtnt_core::CoreError` plus a few
/// verifier-specific failure modes.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Forwarded from `sxtnt-core`. Most failures are relaxed-R1CS
    /// violations.
    #[error("core: {0}")]
    Core(#[from] CoreError),
    /// The proof's scheme tag did not match the scheme the caller
    /// instantiated the verifier with.
    #[error("scheme mismatch: proof says {0:?}, verifier configured for {1:?}")]
    SchemeMismatch(SchemeKind, SchemeKind),
    /// The number of fold steps recorded in the proof did not match
    /// the number of instances the verifier was given.
    #[error("step count mismatch: proof has {got} steps, verifier replayed {expected}")]
    StepCountMismatch {
        /// What the proof claimed.
        got: usize,
        /// What the replay computed.
        expected: usize,
    },
}

/// Top-level verify entry point. Dispatches on the proof's scheme tag
/// and replays the chain. Returns `Ok(())` if and only if every fold
/// step's challenge matches the verifier's transcript replay and the
/// final accumulator satisfies the relaxed-R1CS check.
pub fn verify_proof(
    proof: &FoldingProof,
    instances: &[Accumulator],
    public_input: &[Scalar],
) -> Result<(), VerifyError> {
    if instances.len().saturating_sub(1) != proof.steps.len() {
        return Err(VerifyError::StepCountMismatch {
            got: proof.steps.len(),
            expected: instances.len().saturating_sub(1),
        });
    }
    match proof.scheme {
        SchemeKind::Nova => Nova.verify(proof, instances, public_input).map_err(Into::into),
        SchemeKind::SuperNova => {
            // The caller must supply the selector via the public input
            // tail; for a parameterless reference verify we read the
            // selector back from the proof's step indices.
            let circuits: Vec<u16> = proof
                .steps
                .iter()
                .map(|s| (s.index as u16) % u16::MAX)
                .collect();
            let sn = SuperNova {
                selector: SuperNovaSelector { circuits },
            };
            sn.verify(proof, instances, public_input).map_err(Into::into)
        }
        SchemeKind::HyperNova => {
            // Reference verify treats every lane choice as 1; the
            // production verifier reads the lane value from the
            // proof envelope.
            let hn = HyperNova { lanes: 1 };
            hn.verify(proof, instances, public_input).map_err(Into::into)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use sxtnt_core::accumulator::RelaxedRow;
    use sxtnt_core::commitment::CommitmentKey;
    use sxtnt_core::scheme::Nova;

    #[test]
    fn round_trip_nova() {
        let mut rng = ark_std::test_rng();
        let ck = CommitmentKey::deterministic(b"verifier.test", 4);
        let z: Vec<Scalar> = (0..4).map(|_| Scalar::rand(&mut rng)).collect();
        let ins: Vec<Accumulator> = (0..4)
            .map(|_| {
                let rows: Vec<_> = (0..4)
                    .map(|_| {
                        let az = Scalar::rand(&mut rng);
                        let bz = Scalar::rand(&mut rng);
                        let cz = az * bz;
                        RelaxedRow::from_scalars(&az, &bz, &cz, &Scalar::from(0u64))
                    })
                    .collect();
                Accumulator::fresh(&ck, rows, &z).unwrap()
            })
            .collect();
        let proof = Nova.prove(&ck, &ins, &[Scalar::from(1u64)]).unwrap();
        verify_proof(&proof, &ins, &[Scalar::from(1u64)]).unwrap();
    }
}
// see docs/folding-schemes.md for the tradeoff table.
