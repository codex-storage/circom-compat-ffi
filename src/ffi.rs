use std::{
    any::Any,
    ffi::{c_char, CStr},
    fs::File,
    os::raw::c_void,
    panic::{catch_unwind, AssertUnwindSafe},
};

use ark_bn254::{Bn254, Fr};
use ark_circom::{read_zkey, CircomBuilder, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::ThreadRng, thread_rng};

use ruint::aliases::U256;

type GrothBn = Groth16<Bn254>;

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

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Buffer {
    data: *const u8,
    len: usize,
}

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

pub unsafe extern "C" fn release_buffer(buff_ptr: &mut *mut Buffer) {
    if !buff_ptr.is_null() {
        let buff = &mut Box::from_raw(*buff_ptr);
        let _ = Box::from_raw(buff.data as *mut u8);
        buff.data = std::ptr::null_mut();
        buff.len = 0;
        *buff_ptr = std::ptr::null_mut();
    }
}

unsafe fn to_circom(ctx_ptr: *mut CircomCompatCtx) -> *mut CircomBn254 {
    (*ctx_ptr).circom as *mut CircomBn254
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

/// # Safety
///
#[no_mangle]
#[allow(private_interfaces)]
pub unsafe extern "C" fn prove_circuit(
    ctx_ptr: *mut CircomCompatCtx,
    proof_bytes_ptr: &mut *mut Buffer,
    inputs_bytes_ptr: &mut *mut Buffer,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let circom = &mut *to_circom(ctx_ptr);

        let proving_key = &(*circom.proving_key);
        let rng = &mut (*ctx_ptr).rng;

        let circuit = (*circom.builder).clone().build().unwrap();

        let inputs = circuit.get_public_inputs().unwrap();
        let proof = GrothBn::prove(&proving_key, circuit, rng).unwrap();

        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();

        let mut public_inputs_bytes = Vec::new();
        inputs
            .serialize_compressed(&mut public_inputs_bytes)
            .unwrap();

        // leak the buffers to avoid rust from freeing the pointed to data,
        // clone to avoid bytes from being freed
        let proof_slice = Box::leak(Box::new(proof_bytes.clone())).as_slice();
        let proof_buff = Buffer {
            data: proof_slice.as_ptr() as *const u8,
            len: proof_bytes.len(),
        };

        // leak the buffers to avoid rust from freeing the pointed to data,
        // clone to avoid bytes from being freed
        let input_slice = Box::leak(Box::new(public_inputs_bytes.clone())).as_slice();
        let input_buff = Buffer {
            data: input_slice.as_ptr() as *const u8,
            len: public_inputs_bytes.len(),
        };

        *proof_bytes_ptr = Box::into_raw(Box::new(proof_buff));
        *inputs_bytes_ptr = Box::into_raw(Box::new(input_buff));
    }));

    to_err_code(result)
}

/// # Safety
///
#[no_mangle]
#[allow(private_interfaces)]
pub unsafe extern "C" fn verify_circuit(
    ctx_ptr: *mut CircomCompatCtx,
    proof_bytes_ptr: *const Buffer,
    inputs_bytes_ptr: *const Buffer,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let proof_bytes =
            std::slice::from_raw_parts((*proof_bytes_ptr).data, (*proof_bytes_ptr).len);

        let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
            .map_err(|_| ERR_FAILED_TO_DESERIALIZE_PROOF)
            .unwrap();

        let public_inputs_bytes =
            std::slice::from_raw_parts((*inputs_bytes_ptr).data, (*inputs_bytes_ptr).len);
        let public_inputs: Vec<Fr> =
            CanonicalDeserialize::deserialize_compressed(public_inputs_bytes)
                .map_err(|_| ERR_FAILED_TO_DESERIALIZE_INPUTS)
                .unwrap();

        let circom = &mut *to_circom(ctx_ptr);

        let proving_key = &(*circom.proving_key);
        let pvk = prepare_verifying_key(&proving_key.vk);

        GrothBn::verify_proof(&pvk, &proof, &public_inputs)
            .map_err(|e| e.to_string())
            .unwrap();
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
                let name = CStr::from_ptr(name_ptr).to_str().unwrap();
                let input = U256::from(input);

                let circom = &mut *to_circom(ctx_ptr);
                (*circom.builder).push_input(name, input);
            }));

            to_err_code(result)
        }
    };
}

build_fn!(push_input_numeric_i8, x: i8);
build_fn!(push_input_numeric_u8, x: u8);
build_fn!(push_input_numeric_i16, x: i16);
build_fn!(push_input_numeric_u16, x: u16);
build_fn!(push_input_numeric_i32, x: i32);
build_fn!(push_input_numeric_u32, x: u32);
build_fn!(push_input_numeric_u64, x: u64);

#[cfg(test)]
mod test {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn groth16_proof() {
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
            push_input_numeric_i8(ctx_ptr, a.as_ptr(), 3);

            let b = CString::new("b".as_bytes()).unwrap();
            push_input_numeric_i8(ctx_ptr, b.as_ptr(), 11);

            let mut proof_bytes_ptr: *mut Buffer = std::ptr::null_mut();
            let mut inputs_bytes_ptr: *mut Buffer = std::ptr::null_mut();

            assert!(prove_circuit(ctx_ptr, &mut proof_bytes_ptr, &mut inputs_bytes_ptr) == ERR_OK);

            assert!(proof_bytes_ptr != std::ptr::null_mut());
            assert!((*proof_bytes_ptr).data != std::ptr::null());
            assert!((*proof_bytes_ptr).len > 0);

            assert!(inputs_bytes_ptr != std::ptr::null_mut());
            assert!((*inputs_bytes_ptr).data != std::ptr::null());
            assert!((*inputs_bytes_ptr).len > 0);

            assert!(verify_circuit(ctx_ptr, &(*proof_bytes_ptr), &(*inputs_bytes_ptr)) == ERR_OK);

            release_buffer(&mut proof_bytes_ptr);
            release_buffer(&mut inputs_bytes_ptr);
            release_circom_compat(&mut ctx_ptr);

            assert!(ctx_ptr == std::ptr::null_mut());
            assert!(proof_bytes_ptr == std::ptr::null_mut());
            assert!(inputs_bytes_ptr == std::ptr::null_mut());
        };
    }
}
