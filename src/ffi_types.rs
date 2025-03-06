use std::ptr::slice_from_raw_parts;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalDeserialize;
use ark_std::Zero;

// Helper for converting a PrimeField to little endian byte slice
fn slice_to_point<F: PrimeField>(point: &[u8; 32]) -> F {
    let bigint = F::BigInt::deserialize_uncompressed(&point[..]).expect("always works");
    F::from_bigint(bigint).unwrap()
}

// Helper for converting a PrimeField to its U256 representation for Ethereum compatibility
fn point_to_slice<F: PrimeField>(point: F) -> [u8; 32] {
    let point = point.into_bigint();
    let point_bytes = point.to_bytes_le();
    point_bytes.try_into().expect("always works")
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct G1 {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct G2 {
    pub x: [[u8; 32]; 2],
    pub y: [[u8; 32]; 2],
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct Proof {
    pub a: G1,
    pub b: G2,
    pub c: G1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct VerifyingKey {
    pub alpha1: G1,
    pub beta2: G2,
    pub gamma2: G2,
    pub delta2: G2,
    pub ic: *const G1,
    pub ic_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct Inputs {
    pub elms: *const [u8; 32],
    pub len: usize,
}

impl From<&G1Affine> for G1 {
    fn from(src: &G1Affine) -> Self {
        Self {
            x: point_to_slice(src.x),
            y: point_to_slice(src.y),
        }
    }
}

impl From<&G2Affine> for G2 {
    fn from(src: &G2Affine) -> Self {
        // We should use the `.as_tuple()` method which handles converting
        // the G2 elements to have the second limb first
        Self {
            x: [point_to_slice(src.x.c0), point_to_slice(src.x.c1)],
            y: [point_to_slice(src.y.c0), point_to_slice(src.y.c1)],
        }
    }
}

impl From<&ark_groth16::Proof<Bn254>> for Proof {
    fn from(src: &ark_groth16::Proof<Bn254>) -> Self {
        Self {
            a: (&src.a).into(),
            b: (&src.b).into(),
            c: (&src.c).into(),
        }
    }
}

impl From<G1> for G1Affine {
    fn from(src: G1) -> Self {
        let x: Fq = slice_to_point(&src.x);
        let y: Fq = slice_to_point(&src.y);
        if x.is_zero() && y.is_zero() {
            G1Affine::identity()
        } else {
            G1Affine::new(x, y)
        }
    }
}

impl From<G2> for G2Affine {
    fn from(src: G2) -> G2Affine {
        let c0 = slice_to_point(&src.x[0]);
        let c1 = slice_to_point(&src.x[1]);
        let x = Fq2::new(c0, c1);

        let c0 = slice_to_point(&src.y[0]);
        let c1 = slice_to_point(&src.y[1]);
        let y = Fq2::new(c0, c1);

        if x.is_zero() && y.is_zero() {
            G2Affine::identity()
        } else {
            G2Affine::new(x, y)
        }
    }
}

impl From<Proof> for ark_groth16::Proof<Bn254> {
    fn from(src: Proof) -> ark_groth16::Proof<Bn254> {
        ark_groth16::Proof {
            a: src.a.into(),
            b: src.b.into(),
            c: src.c.into(),
        }
    }
}

impl From<VerifyingKey> for ark_groth16::VerifyingKey<Bn254> {
    fn from(src: VerifyingKey) -> ark_groth16::VerifyingKey<Bn254> {
        ark_groth16::VerifyingKey {
            alpha_g1: src.alpha1.into(),
            beta_g2: src.beta2.into(),
            gamma_g2: src.gamma2.into(),
            delta_g2: src.delta2.into(),
            gamma_abc_g1: unsafe {
                std::slice::from_raw_parts(src.ic, src.ic_len)
                    .iter()
                    .map(|p| (*p).into())
                    .collect()
            },
        }
    }
}

impl From<&ark_groth16::VerifyingKey<Bn254>> for VerifyingKey {
    fn from(vk: &ark_groth16::VerifyingKey<Bn254>) -> Self {
        let mut ic: Vec<G1> = vk.gamma_abc_g1.iter().map(|p| p.into()).collect();
        ic.shrink_to_fit();

        let len = ic.len();
        Self {
            alpha1: G1::from(&vk.alpha_g1),
            beta2: G2::from(&vk.beta_g2),
            gamma2: G2::from(&vk.gamma_g2),
            delta2: G2::from(&vk.delta_g2),
            ic: Box::into_raw(Box::new(ic).into_boxed_slice()) as *const G1,
            ic_len: len,
        }
    }
}

impl From<&[Fr]> for Inputs {
    fn from(src: &[Fr]) -> Self {
        let mut els: Vec<[u8; 32]> = src.iter().map(|point| point_to_slice(*point)).collect();

        els.shrink_to_fit();
        let len = els.len();
        Self {
            elms: Box::leak(els.into_boxed_slice()).as_ptr(),
            len: len,
        }
    }
}

impl From<Inputs> for Vec<Fr> {
    fn from(src: Inputs) -> Self {
        let els: Vec<Fr> = unsafe {
            (&*slice_from_raw_parts(src.elms, src.len))
                .iter()
                .map(|point| slice_to_point(point))
                .collect()
        };

        els
    }
}

#[cfg(test)]
mod test {
    use ark_std::UniformRand;

    use super::*;

    fn fq() -> Fq {
        Fq::from(2)
    }

    fn fr() -> Fr {
        Fr::from(2)
    }

    fn g1() -> G1Affine {
        let rng = &mut ark_std::test_rng();
        G1Affine::rand(rng)
    }

    fn g2() -> G2Affine {
        let rng = &mut ark_std::test_rng();
        G2Affine::rand(rng)
    }

    #[test]
    fn convert_fq() {
        let el = fq();
        let el2 = point_to_slice(el);
        let el3: Fq = slice_to_point(&el2);
        let el4 = point_to_slice(el3);
        assert_eq!(el, el3);
        assert_eq!(el2, el4);
    }

    #[test]
    fn convert_fr() {
        let el = fr();
        let el2 = point_to_slice(el);
        let el3: Fr = slice_to_point(&el2);
        let el4 = point_to_slice(el3);
        assert_eq!(el, el3);
        assert_eq!(el2, el4);
    }

    #[test]
    fn convert_g1() {
        let el = g1();
        let el2 = G1::from(&el);
        let el3: G1Affine = el2.into();
        let el4 = G1::from(&el3);
        assert_eq!(el, el3);
        assert_eq!(el2, el4);
    }

    #[test]
    fn convert_g2() {
        let el = g2();
        let el2 = G2::from(&el);
        let el3: G2Affine = el2.into();
        let el4 = G2::from(&el3);
        assert_eq!(el, el3);
        assert_eq!(el2, el4);
    }

    #[test]
    fn convert_vk() {
        let vk = ark_groth16::VerifyingKey::<Bn254> {
            alpha_g1: g1(),
            beta_g2: g2(),
            gamma_g2: g2(),
            delta_g2: g2(),
            gamma_abc_g1: vec![g1(), g1(), g1()],
        };
        let vk_ffi = &VerifyingKey::from(&vk);
        let ark_vk: ark_groth16::VerifyingKey<Bn254> = (*vk_ffi).into();
        assert_eq!(ark_vk, vk);
    }

    #[test]
    fn convert_proof() {
        let p = ark_groth16::Proof::<Bn254> {
            a: g1(),
            b: g2(),
            c: g1(),
        };
        let p2 = Proof::from(&p);
        let p3 = ark_groth16::Proof::from(p2);
        assert_eq!(p, p3);
    }
}
