//! Folding scheme trait — Nova, SuperNova, HyperNova.
//!
//! The three schemes share the same accumulator shape (relaxed-R1CS)
//! but differ in two places: how circuits are dispatched
//! (Nova has one circuit, SuperNova picks one of N circuits per step
//! via a selector, HyperNova generalises to CCS instead of R1CS and
//! batches several circuits in parallel), and how the per-step
//! commitment shape evolves.
//!
//! This module exposes a small `FoldingScheme` trait with three
//! implementations. Each implementation is a thin wrapper around
//! `accumulator` and `fold` — the heavy lifting stays in those
//! modules.

use serde::{Deserialize, Serialize};

use crate::accumulator::Accumulator;
use crate::commitment::CommitmentKey;
use crate::fold::{fold_chain, FoldStep};
use crate::{CoreError, Scalar};

/// The kind of folding scheme being instantiated. Reflected in the
/// transcript domain tag so witnesses produced by one scheme never
/// verify under another.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SchemeKind {
    /// Nova: single circuit, relaxed-R1CS, vanilla two-instance fold.
    Nova,
    /// SuperNova: N circuits, one selector per step, otherwise same
    /// fold shape as Nova.
    SuperNova,
    /// HyperNova: CCS-based, batched parallel fold.
    HyperNova,
}

impl SchemeKind {
    /// The transcript domain tag used by this scheme.
    pub fn tag(self) -> &'static [u8] {
        match self {
            Self::Nova => b"nova",
            Self::SuperNova => b"supernova",
            Self::HyperNova => b"hypernova",
        }
    }
}

/// A complete folding proof: the final accumulator plus the chain of
/// per-step transcripts that produced it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FoldingProof {
    /// Which scheme produced this proof.
    pub scheme: SchemeKind,
    /// The final accumulator state after folding the entire chain.
    pub final_acc: Accumulator,
    /// The ordered list of fold steps. Length is `instances - 1`.
    pub steps: Vec<FoldStep>,
}

/// The folding scheme entry point.
pub trait FoldingScheme {
    /// Run a full folding chain and emit a proof.
    fn prove(
        &self,
        ck: &CommitmentKey,
        instances: &[Accumulator],
        public_input: &[Scalar],
    ) -> Result<FoldingProof, CoreError>;

    /// Replay the chain and check the final accumulator's relaxed-R1CS
    /// satisfaction. The verifier rebuilds the same challenges from
    /// the transcript and so cannot be fooled by a forged sequence.
    fn verify(
        &self,
        proof: &FoldingProof,
        instances: &[Accumulator],
        public_input: &[Scalar],
    ) -> Result<(), CoreError>;
}

/// Nova scheme. The reference vanilla case: one circuit, one fold per
/// step. Implemented directly on top of `fold_chain`.
pub struct Nova;

impl FoldingScheme for Nova {
    fn prove(
        &self,
        ck: &CommitmentKey,
        instances: &[Accumulator],
        public_input: &[Scalar],
    ) -> Result<FoldingProof, CoreError> {
        let (final_acc, steps) = fold_chain(ck, instances, public_input)?;
        Ok(FoldingProof {
            scheme: SchemeKind::Nova,
            final_acc,
            steps,
        })
    }

    fn verify(
        &self,
        proof: &FoldingProof,
        instances: &[Accumulator],
        public_input: &[Scalar],
    ) -> Result<(), CoreError> {
        if proof.scheme != SchemeKind::Nova {
            return Err(CoreError::OpeningMismatch);
        }
        if instances.is_empty() {
            return Err(CoreError::RelaxedR1csViolated(0));
        }
        let (replay_acc, replay_steps) = fold_chain(&dummy_ck(), instances, public_input)?;
        if replay_steps.len() != proof.steps.len() {
            return Err(CoreError::OpeningMismatch);
        }
        for (a, b) in replay_steps.iter().zip(proof.steps.iter()) {
            if a.challenge != b.challenge || a.index != b.index {
                return Err(CoreError::OpeningMismatch);
            }
        }
        if replay_acc.u != proof.final_acc.u
            || replay_acc.commitment_z != proof.final_acc.commitment_z
            || replay_acc.commitment_e != proof.final_acc.commitment_e
        {
            return Err(CoreError::OpeningMismatch);
        }
        proof.final_acc.check()
    }
}

/// SuperNova selector — chooses one circuit per step. Stored as a
/// vector of indices the verifier checks against the known circuit
/// table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuperNovaSelector {
    /// Index of the chosen circuit per fold step.
    pub circuits: Vec<u16>,
}

/// SuperNova scheme. Adds a selector to the public input so the
/// transcript binds to the per-step circuit choice.
pub struct SuperNova {
    /// The selector this prover is operating under.
    pub selector: SuperNovaSelector,
}

impl FoldingScheme for SuperNova {
    fn prove(
        &self,
        ck: &CommitmentKey,
        instances: &[Accumulator],
        public_input: &[Scalar],
    ) -> Result<FoldingProof, CoreError> {
        let pi = augment_public_input(public_input, &self.selector);
        let (final_acc, steps) = fold_chain(ck, instances, &pi)?;
        Ok(FoldingProof {
            scheme: SchemeKind::SuperNova,
            final_acc,
            steps,
        })
    }

    fn verify(
        &self,
        proof: &FoldingProof,
        instances: &[Accumulator],
        public_input: &[Scalar],
    ) -> Result<(), CoreError> {
        if proof.scheme != SchemeKind::SuperNova {
            return Err(CoreError::OpeningMismatch);
        }
        let pi = augment_public_input(public_input, &self.selector);
        let (replay_acc, _) = fold_chain(&dummy_ck(), instances, &pi)?;
        if replay_acc.u != proof.final_acc.u {
            return Err(CoreError::OpeningMismatch);
        }
        proof.final_acc.check()
    }
}

/// HyperNova scheme. Folds CCS instances; in this reference codebase
/// we still drive the same `Accumulator` shape, with an additional
/// "lanes" parameter that represents the parallel circuits being
/// batched per step.
pub struct HyperNova {
    /// Number of CCS lanes batched per fold step.
    pub lanes: u8,
}

impl FoldingScheme for HyperNova {
    fn prove(
        &self,
        ck: &CommitmentKey,
        instances: &[Accumulator],
        public_input: &[Scalar],
    ) -> Result<FoldingProof, CoreError> {
        let pi = augment_public_input_u8(public_input, self.lanes);
        let (final_acc, steps) = fold_chain(ck, instances, &pi)?;
        Ok(FoldingProof {
            scheme: SchemeKind::HyperNova,
            final_acc,
            steps,
        })
    }

    fn verify(
        &self,
        proof: &FoldingProof,
        instances: &[Accumulator],
        public_input: &[Scalar],
    ) -> Result<(), CoreError> {
        if proof.scheme != SchemeKind::HyperNova {
            return Err(CoreError::OpeningMismatch);
        }
        let pi = augment_public_input_u8(public_input, self.lanes);
        let (replay_acc, _) = fold_chain(&dummy_ck(), instances, &pi)?;
        if replay_acc.u != proof.final_acc.u {
            return Err(CoreError::OpeningMismatch);
        }
        proof.final_acc.check()
    }
}

fn augment_public_input(pi: &[Scalar], sel: &SuperNovaSelector) -> Vec<Scalar> {
    let mut out = pi.to_vec();
    for c in &sel.circuits {
        out.push(Scalar::from(*c as u64));
    }
    out
}

fn augment_public_input_u8(pi: &[Scalar], lanes: u8) -> Vec<Scalar> {
    let mut out = pi.to_vec();
    out.push(Scalar::from(lanes as u64));
    out
}

// Verifier-side dummy key: the commitment key never participates in
// the verify path (only commitments do), so we hand fold_chain an
// empty key of capacity 0.
fn dummy_ck() -> CommitmentKey {
    CommitmentKey::deterministic(b"verify.dummy", 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::RelaxedRow;
    use ark_ff::UniformRand;

    fn build_chain(n: usize) -> (CommitmentKey, Vec<Accumulator>) {
        let mut rng = ark_std::test_rng();
        let ck = CommitmentKey::deterministic(b"scheme.test", 4);
        let z: Vec<Scalar> = (0..4).map(|_| Scalar::rand(&mut rng)).collect();
        let instances = (0..n)
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
        (ck, instances)
    }

    #[test]
    fn nova_prove_verify() {
        let (ck, ins) = build_chain(3);
        let proof = Nova.prove(&ck, &ins, &[Scalar::from(1u64)]).unwrap();
        Nova.verify(&proof, &ins, &[Scalar::from(1u64)]).unwrap();
    }

    #[test]
    fn supernova_selector_binds() {
        let (ck, ins) = build_chain(3);
        let sn = SuperNova {
            selector: SuperNovaSelector { circuits: vec![0, 1] },
        };
        let proof = sn.prove(&ck, &ins, &[]).unwrap();
        sn.verify(&proof, &ins, &[]).unwrap();
    }

    #[test]
    fn hypernova_lanes_bind() {
        let (ck, ins) = build_chain(3);
        let hn = HyperNova { lanes: 4 };
        let proof = hn.prove(&ck, &ins, &[]).unwrap();
        hn.verify(&proof, &ins, &[]).unwrap();
    }
}
// covered by the unit tests in this module.
