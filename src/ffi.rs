use std::{
    any::Any,
    ffi::{c_char, CStr},
    fs::File,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr::slice_from_raw_parts_mut,
};

use ark_bn254::{Bn254, Fr};
use ark_circom::{read_zkey, CircomBuilder, CircomConfig, CircomReduction};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{prepare_verifying_key, Groth16, ProvingKey};
use ark_std::rand::thread_rng;
use ruint::aliases::U256;

use crate::ffi_types::*;

type GrothBn = Groth16<Bn254, CircomReduction>;

pub const ERR_UNKNOWN: i32 = -1;
pub const ERR_OK: i32 = 0;
pub const ERR_WASM_PATH: i32 = 1;
pub const ERR_R1CS_PATH: i32 = 2;
pub const ERR_ZKEY_PATH: i32 = 3;
pub const ERR_INPUT_NAME: i32 = 4;
pub const ERR_INVALID_INPUT: i32 = 5;
pub const ERR_CANT_READ_ZKEY: i32 = 6;
pub const ERR_CIRCOM_BUILDER: i32 = 7;
pub const ERR_FAILED_TO_DESERIALIZE_PROOF: i32 = 8;
pub const ERR_FAILED_TO_DESERIALIZE_INPUTS: i32 = 9;
pub const ERR_FAILED_TO_VERIFY_PROOF: i32 = 10;
pub const ERR_GET_PUB_INPUTS: i32 = 11;
pub const ERR_MAKING_PROOF: i32 = 12;
pub const ERR_SERIALIZE_PROOF: i32 = 13;
pub const ERR_SERIALIZE_INPUTS: i32 = 14;

#[derive(Debug, Clone)]
#[repr(C)]
pub struct CircomBn254Cfg {
    cfg: *mut CircomConfig<Bn254>,
    proving_key: *mut ProvingKey<Bn254>,
    _marker: core::marker::PhantomData<(*mut CircomBn254Cfg, core::marker::PhantomPinned)>,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct CircomBn254 {
    builder: *mut CircomBuilder<Bn254>,
    _marker: core::marker::PhantomData<(*mut CircomBn254, core::marker::PhantomPinned)>,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct CircomCompatCtx {
    circom: *mut CircomBn254,
    _marker: core::marker::PhantomData<(*mut CircomCompatCtx, core::marker::PhantomPinned)>,
}

fn to_err_code(result: Result<i32, Box<dyn Any + Send>>) -> i32 {
    match result {
        Ok(_) => ERR_OK,
        Err(e) => match e.downcast_ref::<i32>() {
            Some(e) => *e,
            None => ERR_UNKNOWN,
        },
    }
}

#[no_mangle]
pub unsafe extern "C" fn duplicate_circom_config(
    orig_cfg_ptr: *mut CircomBn254Cfg,
    cfg_ptr: &mut *mut CircomBn254Cfg,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {

        let cfg = (*(*orig_cfg_ptr).cfg).clone();
        let proving_key = (*(*orig_cfg_ptr).proving_key).clone();

        let circom_bn254_cfg = CircomBn254Cfg {
            cfg: Box::into_raw(Box::new(cfg)),
            proving_key: Box::into_raw(Box::new(proving_key)),
            _marker: std::marker::PhantomData,
        };

        *cfg_ptr = Box::into_raw(Box::new(circom_bn254_cfg));

        ERR_OK
    }));

    to_err_code(result)
}

#[no_mangle]
pub unsafe extern "C" fn init_circom_config_with_checks(
    r1cs_path: *const c_char,
    wasm_path: *const c_char,
    zkey_path: *const c_char,
    sanity_check: bool,
    cfg_ptr: &mut *mut CircomBn254Cfg,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut cfg = CircomConfig::<Bn254>::new(
            CStr::from_ptr(wasm_path)
                .to_str()
                .map_err(|_| ERR_WASM_PATH)
                .unwrap(),
            CStr::from_ptr(r1cs_path)
                .to_str()
                .map_err(|_| ERR_R1CS_PATH)
                .unwrap(),
        )
        .map_err(|_| ERR_CIRCOM_BUILDER)
        .unwrap();

        cfg.sanity_check = sanity_check;
        let proving_key = if !zkey_path.is_null() {
            let mut file = File::open(
                CStr::from_ptr(zkey_path)
                    .to_str()
                    .map_err(|_| ERR_ZKEY_PATH)
                    .unwrap(),
            )
            .unwrap();

            read_zkey(&mut file)
                .map_err(|_| ERR_CANT_READ_ZKEY)
                .unwrap()
                .0
        } else {
            let mut rng = thread_rng();
            let builder = CircomBuilder::new(cfg.clone());
            GrothBn::generate_random_parameters_with_reduction::<_>(
                builder.setup(),
                &mut rng,
            )
            .map_err(|_| ERR_UNKNOWN)
            .unwrap()
        };

        let circom_bn254_cfg = CircomBn254Cfg {
            cfg: Box::into_raw(Box::new(cfg)),
            proving_key: Box::into_raw(Box::new(proving_key)),
            _marker: std::marker::PhantomData,
        };

        *cfg_ptr = Box::into_raw(Box::new(circom_bn254_cfg));

        ERR_OK
    }));

    to_err_code(result)
}

#[no_mangle]
pub unsafe extern "C" fn init_circom_config(
    r1cs_path: *const c_char,
    wasm_path: *const c_char,
    zkey_path: *const c_char,
    cfg_ptr: &mut *mut CircomBn254Cfg,
) -> i32 {
    init_circom_config_with_checks(r1cs_path, wasm_path, zkey_path, false, cfg_ptr)
}

#[no_mangle]
pub unsafe extern "C" fn init_circom_compat(
    cfg_ptr: *mut CircomBn254Cfg,
    ctx_ptr: &mut *mut CircomCompatCtx,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let builder = CircomBuilder::new((*(*cfg_ptr).cfg).clone()); // clone the config
        let circom_bn254 = CircomBn254 {
            builder: Box::into_raw(Box::new(builder)),
            _marker: core::marker::PhantomData,
        };

        let circom_compat_ctx = CircomCompatCtx {
            circom: Box::into_raw(Box::new(circom_bn254)),
            _marker: core::marker::PhantomData,
        };

        *ctx_ptr = Box::into_raw(Box::new(circom_compat_ctx));

        ERR_OK
    }));

    to_err_code(result)
}

#[no_mangle]
pub unsafe extern "C" fn release_circom_compat(ctx_ptr: &mut *mut CircomCompatCtx) {
    if !ctx_ptr.is_null() {
        let ctx = &mut Box::from_raw(*ctx_ptr);

        if !ctx.circom.is_null() {
            let circom = &mut Box::from_raw(ctx.circom);
            let builder = Box::from_raw(circom.builder);
            drop(builder);
        }

        *ctx_ptr = std::ptr::null_mut();
    }
}

#[no_mangle]
pub unsafe extern "C" fn release_cfg(cfg_ptr: &mut *mut CircomBn254Cfg) {
    if !cfg_ptr.is_null() && !(*cfg_ptr).is_null() {
        let cfg = Box::from_raw(*cfg_ptr);
        drop(Box::from_raw((*cfg).proving_key));
        drop(Box::from_raw((*cfg).cfg));
        drop(cfg);
        *cfg_ptr = std::ptr::null_mut();
    }
}

#[no_mangle]
pub unsafe extern "C" fn release_proof(proof_ptr: &mut *mut Proof) {
    if !proof_ptr.is_null() {
        drop(Box::from_raw(*proof_ptr));
        *proof_ptr = std::ptr::null_mut();
    }
}

#[no_mangle]
// Only use if the buffer was allocated by the ffi
pub unsafe extern "C" fn release_inputs(inputs_ptr: &mut *mut Inputs) {
    if !inputs_ptr.is_null() {
        let inputs = Box::from_raw(*inputs_ptr);
        let elms = Box::from_raw(slice_from_raw_parts_mut(
            inputs.elms as *mut [u8; 32],
            inputs.len,
        ));
        drop(elms);
        drop(inputs);
        *inputs_ptr = std::ptr::null_mut();
    }
}

#[no_mangle]
// Only use if the buffer was allocated by the ffi
pub unsafe extern "C" fn release_key(key_ptr: &mut *mut VerifyingKey) {
    if !key_ptr.is_null() {
        let key = Box::from_raw(*key_ptr);
        let ic: Box<[G1]> = Box::from_raw(slice_from_raw_parts_mut(key.ic as *mut G1, key.ic_len));
        drop(ic);
        drop(key);
        *key_ptr = std::ptr::null_mut();
    }
}

unsafe fn to_circom(ctx_ptr: *mut CircomCompatCtx) -> *mut CircomBn254 {
    (*ctx_ptr).circom as *mut CircomBn254
}

#[no_mangle]
pub unsafe extern "C" fn prove_circuit(
    cfg_ptr: *mut CircomBn254Cfg,
    ctx_ptr: *mut CircomCompatCtx,
    proof_ptr: &mut *mut Proof, // inputs_bytes_ptr: &mut *mut Buffer,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let circom = &mut *to_circom(ctx_ptr);
        let proving_key = (*(*cfg_ptr).proving_key).clone();
        let rng = &mut thread_rng();

        let circuit = (*circom.builder)
            .clone()
            .build()
            .map_err(|_| ERR_CIRCOM_BUILDER)
            .unwrap();

        let circom_proof = GrothBn::prove(&proving_key, circuit, rng)
            .map_err(|_| ERR_MAKING_PROOF)
            .unwrap();

        *proof_ptr = Box::leak(Box::new((&circom_proof).into()));

        ERR_OK
    }));

    to_err_code(result)
}

#[no_mangle]
pub unsafe extern "C" fn get_pub_inputs(
    ctx_ptr: *mut CircomCompatCtx,
    inputs_ptr: &mut *mut Inputs, // inputs_bytes_ptr: &mut *mut Buffer,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let circom = &mut *to_circom(ctx_ptr);
        let circuit = (*circom.builder)
            .clone()
            .build()
            .map_err(|_| ERR_CIRCOM_BUILDER)
            .unwrap();

        let inputs = circuit
            .get_public_inputs()
            .ok_or_else(|| ERR_GET_PUB_INPUTS)
            .unwrap();
        *inputs_ptr = Box::leak(Box::new(inputs.as_slice().into()));

        ERR_OK
    }));

    to_err_code(result)
}

#[no_mangle]
pub unsafe extern "C" fn get_verifying_key(
    cfg_ptr: *mut CircomBn254Cfg,
    vk_ptr: &mut *mut VerifyingKey, // inputs_bytes_ptr: &mut *mut Buffer,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let ctx = &mut *cfg_ptr;
        let proving_key = &(*(*ctx).proving_key);
        let vk = prepare_verifying_key(&proving_key.vk).vk;

        *vk_ptr = Box::leak(Box::new((&vk).into()));

        ERR_OK
    }));

    to_err_code(result)
}

#[no_mangle]
pub unsafe extern "C" fn verify_circuit(
    proof: *const Proof,
    inputs: *const Inputs,
    pvk: *const VerifyingKey,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let inputs_vec: Vec<Fr> = (*inputs).into();
        let prepared_key = prepare_verifying_key(&(*pvk).into());

        let passed = GrothBn::verify_proof(&prepared_key, &(*proof).into(), inputs_vec.as_slice())
            .map_err(|_| ERR_FAILED_TO_VERIFY_PROOF)
            .unwrap();

        match passed {
            // println!("proof verified - passed");
            true => ERR_OK,
            // println!("proof verified - failed");
            false => ERR_FAILED_TO_VERIFY_PROOF,
        }
    }));

    // println!("result: {:?}", result);
    match result {
        Err(e) => to_err_code(Err(e)),
        Ok(c) => c,
    }
}

#[no_mangle]
pub unsafe extern "C" fn push_input_u256_array(
    ctx_ptr: *mut CircomCompatCtx,
    name_ptr: *const c_char,
    input_ptr: *const u8,
    len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let name = CStr::from_ptr(name_ptr)
            .to_str()
            .map_err(|_| ERR_INPUT_NAME)
            .unwrap();

        let slice = std::slice::from_raw_parts(input_ptr, len);
        let inputs = slice
            .chunks(U256::BYTES)
            .map(|c| U256::try_from_le_slice(c).ok_or(ERR_INVALID_INPUT).unwrap())
            .collect::<Vec<U256>>();

        let circom = &mut *to_circom(ctx_ptr);
        inputs
            .iter()
            .for_each(|c| (*circom.builder).push_input(name, *c));

        ERR_OK
    }));

    to_err_code(result)
}

macro_rules! build_fn
{
    ($name:tt, $($v:ident: $t:ty),*) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            ctx_ptr: *mut CircomCompatCtx,
            name_ptr: *const c_char,
            input: $($t),*
        ) -> i32 {
            let result = catch_unwind(AssertUnwindSafe(|| {
                let name = CStr::from_ptr(name_ptr).to_str().map_err(|_| ERR_INPUT_NAME).unwrap();
                let input = U256::from(input);

                let circom = &mut *to_circom(ctx_ptr);
                (*circom.builder).push_input(name, input);

                ERR_OK
            }));

            to_err_code(result)
        }
    };
}

build_fn!(push_input_i8, x: i8);
build_fn!(push_input_u8, x: u8);
build_fn!(push_input_i16, x: i16);
build_fn!(push_input_u16, x: u16);
build_fn!(push_input_i32, x: i32);
build_fn!(push_input_u32, x: u32);
build_fn!(push_input_u64, x: u64);

#[cfg(test)]
mod test {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn proof_verify() {
        let r1cs_path = CString::new("./fixtures/circom2_multiplier2.r1cs".as_bytes()).unwrap();
        let wasm_path = CString::new("./fixtures/circom2_multiplier2.wasm".as_bytes()).unwrap();
        let zkey_path = CString::new("./fixtures/test.zkey".as_bytes()).unwrap();

        unsafe {
            let mut cfg_ptr: *mut CircomBn254Cfg = std::ptr::null_mut();
            init_circom_config(
                r1cs_path.as_ptr(),
                wasm_path.as_ptr(),
                zkey_path.as_ptr(),
                &mut cfg_ptr,
            );

            assert!(cfg_ptr != std::ptr::null_mut());

            let mut ctx_ptr: *mut CircomCompatCtx = std::ptr::null_mut();
            init_circom_compat(cfg_ptr, &mut ctx_ptr);

            assert!(ctx_ptr != std::ptr::null_mut());

            let a = CString::new("a".as_bytes()).unwrap();
            push_input_i8(ctx_ptr, a.as_ptr(), 3);

            let b = CString::new("b".as_bytes()).unwrap();
            push_input_i8(ctx_ptr, b.as_ptr(), 11);

            let mut proof_ptr: *mut Proof = std::ptr::null_mut();
            let mut inputs_ptr: *mut Inputs = std::ptr::null_mut();
            let mut vk_ptr: *mut VerifyingKey = std::ptr::null_mut();

            assert!(get_pub_inputs(ctx_ptr, &mut inputs_ptr) == ERR_OK);
            assert!(inputs_ptr != std::ptr::null_mut());

            assert!(prove_circuit(cfg_ptr, ctx_ptr, &mut proof_ptr) == ERR_OK);
            assert!(proof_ptr != std::ptr::null_mut());

            assert!(get_verifying_key(cfg_ptr, &mut vk_ptr) == ERR_OK);
            assert!(vk_ptr != std::ptr::null_mut());

            assert!(verify_circuit(&(*proof_ptr), &(*inputs_ptr), &(*vk_ptr)) == ERR_OK);

            release_inputs(&mut inputs_ptr);
            assert!(inputs_ptr == std::ptr::null_mut());

            release_proof(&mut proof_ptr);
            assert!(proof_ptr == std::ptr::null_mut());

            release_key(&mut vk_ptr);
            assert!(vk_ptr == std::ptr::null_mut());

            release_circom_compat(&mut ctx_ptr);
            assert!(ctx_ptr == std::ptr::null_mut());

            release_cfg(&mut cfg_ptr);
            assert!(cfg_ptr == std::ptr::null_mut());
        };
    }

    #[test]
    fn proof_verify_with_zkey() {
        let r1cs_path = CString::new("./fixtures/mycircuit.r1cs".as_bytes()).unwrap();
        let wasm_path = CString::new("./fixtures/mycircuit.wasm".as_bytes()).unwrap();
        let zkey_path = CString::new("./fixtures/test.zkey".as_bytes()).unwrap();

        unsafe {
            let mut cfg_ptr: *mut CircomBn254Cfg = std::ptr::null_mut();
            init_circom_config(
                r1cs_path.as_ptr(),
                wasm_path.as_ptr(),
                zkey_path.as_ptr(),
                &mut cfg_ptr,
            );

            assert!(cfg_ptr != std::ptr::null_mut());

            let mut ctx_ptr: *mut CircomCompatCtx = std::ptr::null_mut();
            init_circom_compat(cfg_ptr, &mut ctx_ptr);

            assert!(ctx_ptr != std::ptr::null_mut());

            let a = CString::new("a".as_bytes()).unwrap();
            push_input_i8(ctx_ptr, a.as_ptr(), 3);

            let b = CString::new("b".as_bytes()).unwrap();
            push_input_i8(ctx_ptr, b.as_ptr(), 11);

            let mut proof_ptr: *mut Proof = std::ptr::null_mut();
            let mut inputs_ptr: *mut Inputs = std::ptr::null_mut();
            let mut vk_ptr: *mut VerifyingKey = std::ptr::null_mut();

            assert!(get_pub_inputs(ctx_ptr, &mut inputs_ptr) == ERR_OK);
            assert!(inputs_ptr != std::ptr::null_mut());

            assert!(prove_circuit(cfg_ptr, ctx_ptr, &mut proof_ptr) == ERR_OK);
            assert!(proof_ptr != std::ptr::null_mut());

            assert!(get_verifying_key(cfg_ptr, &mut vk_ptr) == ERR_OK);
            assert!(vk_ptr != std::ptr::null_mut());

            assert!(verify_circuit(&(*proof_ptr), &(*inputs_ptr), &(*vk_ptr)) == ERR_OK);

            release_inputs(&mut inputs_ptr);
            assert!(inputs_ptr == std::ptr::null_mut());

            release_proof(&mut proof_ptr);
            assert!(proof_ptr == std::ptr::null_mut());

            release_key(&mut vk_ptr);
            assert!(vk_ptr == std::ptr::null_mut());

            release_circom_compat(&mut ctx_ptr);
            assert!(ctx_ptr == std::ptr::null_mut());

            release_cfg(&mut cfg_ptr);
            assert!(cfg_ptr == std::ptr::null_mut());
        };
    }
}
