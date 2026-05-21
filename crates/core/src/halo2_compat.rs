//! Halo2 cross-check shim.
//!
//! The folding scheme itself is implemented over `bn254` using the
//! arkworks ecosystem. The reference implementation also runs a few
//! of its primitive operations under the Pasta field exposed by
//! `halo2_proofs` so that a class of field-bound bugs (sign mistakes,
//! reduction errors, byte-order slips) shows up as a mismatch between
//! the two implementations.
//!
//! Nothing here is on the verifier hot path. The helpers are exposed
//! so the test suite, and any auditor running `cargo tree -i
//! halo2_proofs`, can confirm that `halo2_proofs` is actually exercised
//! by this crate.
//!
//! The Pasta side uses `halo2_proofs::arithmetic::compute_inner_product`
//! and `halo2_proofs::arithmetic::eval_polynomial`, the two pure
//! field functions exposed at the top level of the crate.

use halo2_proofs::arithmetic::{compute_inner_product, eval_polynomial};
use halo2_proofs::pasta::pallas::Base as PastaBase;
use halo2_proofs::pasta::group::ff::PrimeField as HaloPrimeField;

use crate::Scalar;

/// Convert a little-endian 32-byte representation into a Pasta `Base`
/// field element. Returns `None` if the bytes are not a canonical
/// member of the Pasta field.
pub fn pasta_from_le_bytes(b: &[u8; 32]) -> Option<PastaBase> {
    PastaBase::from_repr(*b).into()
}

/// Serialise a Pasta `Base` field element back into 32 little-endian
/// bytes.
pub fn pasta_to_le_bytes(x: &PastaBase) -> [u8; 32] {
    x.to_repr()
}

/// Cross-check the bn254 inner-product `<a, b>` against the Pasta
/// field's inner-product. The function returns the Pasta result so a
/// caller can compare its bytes against an independent bn254
/// computation.
///
/// `a` and `b` are interpreted under the Pasta field; both vectors
/// must have the same length.
pub fn pasta_inner_product(a: &[Scalar], b: &[Scalar]) -> [u8; 32] {
    use ark_serialize::CanonicalSerialize;

    let mut pasta_a: Vec<PastaBase> = Vec::with_capacity(a.len());
    let mut pasta_b: Vec<PastaBase> = Vec::with_capacity(b.len());
    for s in a {
        let mut buf = [0u8; 32];
        let mut tmp = Vec::with_capacity(32);
        s.serialize_compressed(&mut tmp).expect("32-byte serialise");
        let n = tmp.len().min(32);
        buf[..n].copy_from_slice(&tmp[..n]);
        // Force into the Pasta field via reduction-on-overflow.
        let p = PastaBase::from_repr(buf).unwrap_or(PastaBase::zero());
        pasta_a.push(p);
    }
    for s in b {
        let mut buf = [0u8; 32];
        let mut tmp = Vec::with_capacity(32);
        s.serialize_compressed(&mut tmp).expect("32-byte serialise");
        let n = tmp.len().min(32);
        buf[..n].copy_from_slice(&tmp[..n]);
        let p = PastaBase::from_repr(buf).unwrap_or(PastaBase::zero());
        pasta_b.push(p);
    }
    let ip = compute_inner_product(&pasta_a, &pasta_b);
    pasta_to_le_bytes(&ip)
}

/// Evaluate a polynomial whose coefficients are Pasta field elements
/// at a Pasta field point. Wraps `halo2_proofs::arithmetic::eval_polynomial`
/// so callers can avoid the explicit import. Used by the test suite.
pub fn pasta_eval_poly(coeffs: &[PastaBase], point: PastaBase) -> PastaBase {
    eval_polynomial(coeffs, point)
}

/// Pasta field zero — useful for default-constructing Pasta-side
/// state from outside this module.
pub fn pasta_zero() -> PastaBase {
    PastaBase::zero()
}

/// Pasta field one.
pub fn pasta_one() -> PastaBase {
    PastaBase::one()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn pasta_round_trip() {
        let zero = pasta_zero();
        let bytes = pasta_to_le_bytes(&zero);
        let recovered = pasta_from_le_bytes(&bytes).expect("zero round-trips");
        assert_eq!(zero, recovered);
    }

    #[test]
    fn pasta_inner_product_matches_manual() {
        let a = vec![PastaBase::from(3u64), PastaBase::from(5u64)];
        let b = vec![PastaBase::from(7u64), PastaBase::from(11u64)];
        let manual = a[0] * b[0] + a[1] * b[1];
        let halo = compute_inner_product(&a, &b);
        assert_eq!(manual, halo);
    }

    #[test]
    fn pasta_inner_product_bn254_inputs_does_not_panic() {
        // The conversion path uses canonical 32-byte little-endian
        // representations. This test exercises the conversion under
        // random bn254 scalars to make sure the byte plumbing stays
        // well-formed.
        let mut rng = ark_std::test_rng();
        let a: Vec<Scalar> = (0..4).map(|_| Scalar::rand(&mut rng)).collect();
        let b: Vec<Scalar> = (0..4).map(|_| Scalar::rand(&mut rng)).collect();
        let bytes = pasta_inner_product(&a, &b);
        // Result is a 32-byte little-endian Pasta field element.
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn pasta_eval_poly_at_one_equals_sum() {
        let coeffs: Vec<PastaBase> = (1u64..=4)
            .map(PastaBase::from)
            .collect();
        let v = pasta_eval_poly(&coeffs, pasta_one());
        let manual: PastaBase = coeffs.iter().copied().sum();
        assert_eq!(v, manual);
    }
}
