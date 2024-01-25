use std::{
    any::Any, ffi::{c_char, CStr}, fs::File, os::raw::c_void, panic::{catch_unwind, AssertUnwindSafe}, ptr::slice_from_raw_parts_mut
};

use ark_bn254::{Bn254, Fr};
use ark_circom::{read_zkey, CircomBuilder, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{prepare_verifying_key, Groth16, ProvingKey};
use ark_std::rand::{rngs::ThreadRng, thread_rng};
use ruint::aliases::U256;

use crate::ffi_types::*;

type GrothBn = Groth16<Bn254>;

#[derive(Debug, Clone)]
// #[repr(C)]
struct CircomBn254 {
    builder: *mut CircomBuilder<Bn254>,
    proving_key: *mut ProvingKey<Bn254>,
    _marker: core::marker::PhantomData<(*mut CircomBn254, core::marker::PhantomPinned)>,
}

#[derive(Debug, Clone)]
struct CircomCompatCtx {
    circom: *mut c_void,
    rng: ThreadRng,
    _marker: core::marker::PhantomData<(*mut CircomCompatCtx, core::marker::PhantomPinned)>,
}

fn to_err_code(result: Result<(), Box<dyn Any + Send>>) -> i32 {
    match result {
        Ok(_) => ERR_OK,
        Err(e) => match e.downcast_ref::<i32>() {
            Some(e) => *e,
            None => ERR_UNKNOWN,
        },
    }
}

/// # Safety
///
#[no_mangle]
#[allow(private_interfaces)]
pub unsafe extern "C" fn init_circom_compat(
    r1cs_path: *const c_char,
    wasm_path: *const c_char,
    zkey_path: *const c_char,
    ctx_ptr: &mut *mut CircomCompatCtx,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut rng = thread_rng(); // TODO: use a shared rng - how?
        let builder = CircomBuilder::new(
            CircomConfig::<Bn254>::new(
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
            .unwrap(),
        );

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
            Groth16::<Bn254>::generate_random_parameters_with_reduction::<_>(
                builder.setup(),
                &mut rng,
            )
            .map_err(|_| ERR_UNKNOWN)
            .unwrap()
        };

        let circom_bn254 = CircomBn254 {
            builder: Box::into_raw(Box::new(builder)),
            proving_key: Box::into_raw(Box::new(proving_key)),
            _marker: core::marker::PhantomData,
        };

        let circom_compat_ctx = CircomCompatCtx {
            circom: Box::into_raw(Box::new(circom_bn254)) as *mut c_void,
            rng: rng,
            _marker: core::marker::PhantomData,
        };

        *ctx_ptr = Box::into_raw(Box::new(circom_compat_ctx));
    }));

    to_err_code(result)
}

#[no_mangle]
#[allow(private_interfaces)]
pub unsafe extern "C" fn release_circom_compat(ctx_ptr: &mut *mut CircomCompatCtx) {
    if !ctx_ptr.is_null() {
        let ctx = &mut Box::from_raw(*ctx_ptr);
        if !ctx.circom.is_null() {
            let circom = &mut Box::from_raw(ctx.circom as *mut CircomBn254);
            let _ = Box::from_raw(circom.builder);
            let _ = Box::from_raw(circom.proving_key);
            if !circom.builder.is_null() {
                circom.builder = std::ptr::null_mut()
            };
            if !circom.proving_key.is_null() {
                circom.proving_key = std::ptr::null_mut()
            };
            ctx.circom = std::ptr::null_mut();
            *ctx_ptr = std::ptr::null_mut();
        }
    }
}

#[no_mangle]
// Only use if the buffer was allocated by the ffi
pub unsafe extern "C" fn release_buffer(buff_ptr: &mut *mut Buffer) {
    if !buff_ptr.is_null() {
        let buff = Box::from_raw(*buff_ptr);
        let data = Box::from_raw(slice_from_raw_parts_mut(buff.data as *mut u8, buff.len));
        drop(data);
        drop(buff);
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

/// # Safety
///
#[no_mangle]
#[allow(private_interfaces)]
pub unsafe extern "C" fn prove_circuit(
    ctx_ptr: *mut CircomCompatCtx,
    proof_ptr: &mut *mut Proof, // inputs_bytes_ptr: &mut *mut Buffer,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let circom = &mut *to_circom(ctx_ptr);
        let proving_key = &(*circom.proving_key);
        let rng = &mut (*ctx_ptr).rng;

        let circuit = (*circom.builder)
            .clone()
            .build()
            .map_err(|_| ERR_CIRCOM_BUILDER)
            .unwrap();

        let circom_proof = GrothBn::prove(proving_key, circuit, rng)
            .map_err(|_| ERR_MAKING_PROOF)
            .unwrap();

        *proof_ptr = Box::leak(Box::new((&circom_proof).into()));
    }));

    to_err_code(result)
}

/// # Safety
///
#[no_mangle]
#[allow(private_interfaces)]
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
    }));

    to_err_code(result)
}

/// # Safety
///
#[no_mangle]
#[allow(private_interfaces)]
pub unsafe extern "C" fn get_verifying_key(
    ctx_ptr: *mut CircomCompatCtx,
    vk_ptr: &mut *mut VerifyingKey, // inputs_bytes_ptr: &mut *mut Buffer,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let circom = &mut *to_circom(ctx_ptr);
        let proving_key = &(*circom.proving_key);
        let vk = prepare_verifying_key(&proving_key.vk).vk;

        *vk_ptr = Box::leak(Box::new((&vk).into()));
    }));

    to_err_code(result)
}

/// # Safety
///
#[no_mangle]
#[allow(private_interfaces)]
pub unsafe extern "C" fn verify_circuit(
    proof: *const Proof,
    inputs: *const Inputs,
    pvk: *const VerifyingKey,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let inputs_vec: Vec<Fr> = (*inputs).into();
        let prepared_key = prepare_verifying_key(&(*pvk).into());
        GrothBn::verify_proof(&prepared_key, &(*proof).into(), inputs_vec.as_slice())
            .map_err(|_| ERR_FAILED_TO_VERIFY_PROOF)
            .unwrap();
    }));

    to_err_code(result)
}

/// # Safety
///
#[no_mangle]
#[allow(private_interfaces)]
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

        let input = {
            let slice = std::slice::from_raw_parts(input_ptr, len);
            slice
                .chunks(U256::BYTES)
                .map(|c| U256::try_from_le_slice(c).ok_or(ERR_INVALID_INPUT).unwrap())
                .collect::<Vec<U256>>()
        };

        let circom = &mut *to_circom(ctx_ptr);
        input
            .iter()
            .for_each(|c| (*circom.builder).push_input(name, *c));
    }));

    to_err_code(result)
}

macro_rules! build_fn
{
    ($name:tt, $($v:ident: $t:ty),*) => {
        #[no_mangle]
        #[allow(private_interfaces)]
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
        let r1cs_path = CString::new("./fixtures/mycircuit.r1cs".as_bytes()).unwrap();
        let wasm_path = CString::new("./fixtures/mycircuit.wasm".as_bytes()).unwrap();

        unsafe {
            let mut ctx_ptr: *mut CircomCompatCtx = std::ptr::null_mut();
            init_circom_compat(
                r1cs_path.as_ptr(),
                wasm_path.as_ptr(),
                std::ptr::null(),
                &mut ctx_ptr,
            );

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

            assert!(prove_circuit(ctx_ptr, &mut proof_ptr) == ERR_OK);
            assert!(proof_ptr != std::ptr::null_mut());

            assert!(get_verifying_key(ctx_ptr, &mut vk_ptr) == ERR_OK);
            assert!(vk_ptr != std::ptr::null_mut());

            assert!(verify_circuit(&(*proof_ptr), &(*inputs_ptr), &(*vk_ptr)) == ERR_OK);

            release_inputs(&mut inputs_ptr);
            assert!(inputs_ptr == std::ptr::null_mut());

            release_proof(&mut proof_ptr);
            assert!(proof_ptr == std::ptr::null_mut());

            release_key(&mut vk_ptr);
            assert!(vk_ptr == std::ptr::null_mut());
        };
    }
}
