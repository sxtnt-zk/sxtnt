# Threat model

What SXTNT defends against, and what it explicitly does not.

## In scope

### Forged fold sequences

The transcript binds every absorb in order. A prover that rearranges,
omits, or fabricates a step produces a challenge sequence that does
not match the verifier's replay, and the proof is rejected.

### Witness substitution

The accumulator carries Pedersen commitments to both `z` and `E`. A
prover that wants to swap in a different witness has to find a second
opening of the same commitment — by the binding property of Pedersen
over a prime-order group, this is at least as hard as discrete log on
bn254 G1.

### Replay across schemes

The transcript domain tag (`nova`, `supernova`, `hypernova`) is mixed
into every fold challenge, and the on-chain `proof_digest` binds the
scheme tag too. A proof produced under one scheme cannot be replayed
against a registry initialised for another.

### Replay across protocols

The top-level domain string `sxtnt.fold.v1` is the first thing every
transcript absorbs. A SXTNT proof cannot be replayed against any
other protocol that uses a Fiat-Shamir transcript over `blake3` —
their domain string differs, so their challenges differ.

## Out of scope

### Side channels on the prover

The reference implementation does not claim constant-time field or
curve operations. A prover running on hostile hardware can leak its
witness through timing, cache, or power. If you need a side-channel
hardened prover, swap the `ark-bn254` backend for a constant-time
implementation; the rest of the crate is unchanged.

### Quantum adversaries

The discrete-log security of bn254 is the bottleneck. A quantum
adversary with a sufficiently large Shor implementation breaks the
binding property of the commitment scheme. SXTNT is not
post-quantum.

### Trusted setup

The Pedersen commitment key in this reference is derived
deterministically from a domain label — no trusted setup. Production
deployments that swap in a KZG-based commitment scheme inherit
whatever setup that scheme requires. We do not currently ship a
KZG variant.

### Verifier denial of service

A relying party who accepts arbitrary proofs from arbitrary clients
can be made to do unbounded work. The on-chain `accept_proof`
instruction caps work per call by recomputing only the canonical
digest; the full relaxed-R1CS replay happens off-chain. Off-chain
verifiers should rate-limit and bound chain length to defend against
DoS.

### Bugs in circuit definitions

SXTNT proves what the circuit says. If the circuit is wrong, the
proof is faithfully wrong. The marketplace ships a small set of
audited circuit templates; rolling your own circuit and posting it to
the marketplace is at your own risk.

## Audit guidance

If you are auditing this code, the highest-value targets are:

1. The cross-product correction in `Accumulator::merge`. Get this
   wrong and the relaxed-R1CS check stops being closed under folding.
2. The transcript wiring in `crates/verifier/src/transcript.rs`. Any
   absorb the prover does and the verifier doesn't (or vice versa) is
   a soundness break.
3. The `proof_digest` byte layout — both the Rust and the TypeScript
   sides. Drift between them means the on-chain digest no longer
   binds what the prover claims.

The test suite under `cargo test --workspace` exercises every public
entry point; the CI workflow under `.github/workflows/ci.yml` runs
the same checks on every push.

<!-- the lane parameter only applies to HyperNova. -->
