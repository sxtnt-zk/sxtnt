# Folding schemes — Nova, SuperNova, HyperNova

The three folding scheme variants implemented in `sxtnt-core` differ in
two places: how circuits are dispatched per step, and what constraint
system the accumulator carries. Below is a short side-by-side of the
trade-offs.

## Nova

Single circuit `F`. Each step folds one fresh relaxed-R1CS instance
`(A, B, C)` into a running accumulator with the standard

```
acc.u_new = acc.u + r * fresh.u
acc.row_i_new = acc.row_i + r * fresh.row_i  (component-wise)
```

Pros: smallest fold step, simplest verifier, easiest audit surface.

Cons: every step pays the cost of the full circuit `F`, even when the
step only needs a fraction of it.

## SuperNova

Generalises Nova to N circuits `F_1, ..., F_N`. Per step, the prover
picks one circuit via a selector — the per-step circuit choice is
absorbed into the Fiat-Shamir transcript so the verifier sees it.

Pros: pay only for the circuit you actually need this step. Good fit
for workloads where the inner computation is heterogeneous (e.g. a
zkVM with multiple opcode subcircuits).

Cons: verifier maintains N times the verification key, and the
selector adds one extra absorb per step.

## HyperNova

Replaces R1CS with the more general **CCS** (Customizable Constraint
System) representation. CCS supports higher-degree constraints
natively, which means circuits that would have needed many auxiliary
R1CS rows can collapse into fewer CCS rows. HyperNova also folds
multiple CCS instances per step in parallel — the "lanes" parameter.

Pros: tighter representation of arithmetic-heavy circuits, parallel
fold cuts wall-clock for batch workloads.

Cons: the verifier is more complex; higher-degree constraints are
harder to audit by hand.

## When to pick which

| Workload | Best fit |
| --- | --- |
| Single tight inner loop, repeated millions of times | Nova |
| Heterogeneous instruction set (zkVM, opcode dispatch) | SuperNova |
| Arithmetic-heavy circuits, batch parallelism available | HyperNova |

This repository wires all three to the same `Accumulator` shape so a
client can switch schemes by changing one enum value. The on-chain
`ProofRegistry` records which scheme accepted each proof, so a relying
party can filter by scheme when reading the log.

## Reference papers

* Nova: [eprint.iacr.org/2021/370](https://eprint.iacr.org/2021/370)
* SuperNova: [eprint.iacr.org/2022/1758](https://eprint.iacr.org/2022/1758)
* HyperNova: [eprint.iacr.org/2023/573](https://eprint.iacr.org/2023/573)

The implementation in `crates/core` follows the relaxed-R1CS
formulation in the Nova paper. SuperNova and HyperNova are layered on
top: the per-step selector and the lane parameter are absorbed into
the transcript, but the underlying merge math is the same.
