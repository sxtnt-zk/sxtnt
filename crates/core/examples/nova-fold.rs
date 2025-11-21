//! End-to-end example: build a chain of relaxed-R1CS instances, fold
//! them with the Nova scheme, and verify the resulting proof.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p sxtnt-core --example nova-fold
//! ```
//!
//! The example stays deliberately small — four instances of four rows
//! each, satisfied by a hand-picked witness. The point is to exercise
//! the full prove/verify loop in under a hundred lines, not to ship a
//! production circuit.

use ark_ff::UniformRand;
use sxtnt_core::accumulator::{Accumulator, RelaxedRow};
use sxtnt_core::commitment::CommitmentKey;
use sxtnt_core::scheme::{FoldingScheme, Nova};
use sxtnt_core::Scalar;

fn main() {
    let mut rng = ark_std::test_rng();

    // Pick a commitment key and a single shared witness vector.
    let ck = CommitmentKey::deterministic(b"example.nova", 4);
    let z: Vec<Scalar> = (0..4).map(|_| Scalar::rand(&mut rng)).collect();

    // Build four satisfied instances.
    let instances: Vec<Accumulator> = (0..4)
        .map(|i| {
            let rows: Vec<RelaxedRow> = (0..4)
                .map(|_| {
                    let az = Scalar::rand(&mut rng);
                    let bz = Scalar::rand(&mut rng);
                    let cz = az * bz; // satisfied: az * bz - 1 * cz = 0
                    RelaxedRow::from_scalars(&az, &bz, &cz, &Scalar::from(0u64))
                })
                .collect();
            let acc = Accumulator::fresh(&ck, rows, &z).expect("fresh accumulator");
            acc.check().expect("instance is satisfied");
            println!("instance {i}: step={} rows={}", acc.step, acc.rows.len());
            acc
        })
        .collect();

    // Public input — anything that ties this proof to its context.
    // Here we use the unix-epoch-style step counter.
    let pi: Vec<Scalar> = (0..2).map(|i| Scalar::from(i as u64)).collect();

    // Fold.
    let proof = Nova
        .prove(&ck, &instances, &pi)
        .expect("Nova prove succeeds");
    println!(
        "proof: scheme={:?} steps={} final.u_step={}",
        proof.scheme,
        proof.steps.len(),
        proof.final_acc.step,
    );

    // Verify.
    Nova.verify(&proof, &instances, &pi).expect("Nova verify accepts");
    println!("verify: ok");
}
