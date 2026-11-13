//! wasm32 ABI.
//!
//! No allocator is exposed. The JavaScript wrapper writes seeds into fixed
//! input buffers and reads results from fixed output buffers. This keeps the
//! core `no_std` and allocation-free while still being easy to call from a
//! browser or Node without any external tooling.

#![no_std]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

use clasp_photon_core::{keccak, mlkem, poly};

static mut SEED: [u8; 32] = [0u8; 32];
static mut Z: [u8; 32] = [0u8; 32];
static mut RANDOMNESS: [u8; 32] = [0u8; 32];
static mut PUBLIC_KEY: [u8; mlkem::PUBLIC_KEY_BYTES] = [0u8; mlkem::PUBLIC_KEY_BYTES];
static mut SECRET_KEY: [u8; mlkem::SECRET_KEY_BYTES] = [0u8; mlkem::SECRET_KEY_BYTES];
static mut CIPHERTEXT: [u8; mlkem::CIPHERTEXT_BYTES] = [0u8; mlkem::CIPHERTEXT_BYTES];
static mut SHARED_SECRET: [u8; mlkem::SHARED_SECRET_BYTES] = [0u8; mlkem::SHARED_SECRET_BYTES];
static mut INPUT: [u8; 4096] = [0u8; 4096];
static mut INPUT_LEN: usize = 0;
static mut DIGEST: [u8; 32] = [0u8; 32];
static mut NTT_BUFFER: [i32; poly::N] = [0i32; poly::N];

#[no_mangle]
pub extern "C" fn photon_seed_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(SEED) as *mut u8
}

#[no_mangle]
pub extern "C" fn photon_z_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(Z) as *mut u8
}

#[no_mangle]
pub extern "C" fn photon_randomness_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(RANDOMNESS) as *mut u8
}

#[no_mangle]
pub extern "C" fn photon_pk_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(PUBLIC_KEY) as *mut u8
}

#[no_mangle]
pub extern "C" fn photon_sk_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(SECRET_KEY) as *mut u8
}

#[no_mangle]
pub extern "C" fn photon_ct_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(CIPHERTEXT) as *mut u8
}

#[no_mangle]
pub extern "C" fn photon_ss_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(SHARED_SECRET) as *mut u8
}

#[no_mangle]
pub extern "C" fn photon_input_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(INPUT) as *mut u8
}

#[no_mangle]
pub extern "C" fn photon_input_set_len(len: usize) {
    unsafe {
        INPUT_LEN = core::cmp::min(len, 4096);
    }
}

#[no_mangle]
pub extern "C" fn photon_digest_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(DIGEST) as *mut u8
}

#[no_mangle]
pub extern "C" fn photon_ntt_buffer_ptr() -> *mut i32 {
    core::ptr::addr_of_mut!(NTT_BUFFER) as *mut i32
}

#[no_mangle]
pub extern "C" fn photon_ntt() {
    unsafe {
        let mut buffer = [0i32; poly::N];
        buffer.copy_from_slice(&*core::ptr::addr_of!(NTT_BUFFER));
        poly::ntt(&mut buffer);
        NTT_BUFFER = buffer;
    }
}

#[no_mangle]
pub extern "C" fn photon_inv_ntt() {
    unsafe {
        let mut buffer = [0i32; poly::N];
        buffer.copy_from_slice(&*core::ptr::addr_of!(NTT_BUFFER));
        poly::inv_ntt(&mut buffer);
        NTT_BUFFER = buffer;
    }
}

#[no_mangle]
pub extern "C" fn photon_keygen() -> i32 {
    unsafe {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&*core::ptr::addr_of!(SEED));
        let mut z = [0u8; 32];
        z.copy_from_slice(&*core::ptr::addr_of!(Z));
        let mut pk = [0u8; mlkem::PUBLIC_KEY_BYTES];
        let mut sk = [0u8; mlkem::SECRET_KEY_BYTES];
        mlkem::keygen(&seed, &z, &mut pk, &mut sk);
        PUBLIC_KEY = pk;
        SECRET_KEY = sk;
    }
    0
}

#[no_mangle]
pub extern "C" fn photon_encaps() -> i32 {
    unsafe {
        let mut pk = [0u8; mlkem::PUBLIC_KEY_BYTES];
        pk.copy_from_slice(&*core::ptr::addr_of!(PUBLIC_KEY));
        let mut randomness = [0u8; 32];
        randomness.copy_from_slice(&*core::ptr::addr_of!(RANDOMNESS));
        let mut ct = [0u8; mlkem::CIPHERTEXT_BYTES];
        let mut ss = [0u8; mlkem::SHARED_SECRET_BYTES];
        mlkem::encaps(&pk, &randomness, &mut ct, &mut ss);
        CIPHERTEXT = ct;
        SHARED_SECRET = ss;
    }
    0
}

#[no_mangle]
pub extern "C" fn photon_decaps() -> i32 {
    unsafe {
        let mut sk = [0u8; mlkem::SECRET_KEY_BYTES];
        sk.copy_from_slice(&*core::ptr::addr_of!(SECRET_KEY));
        let mut ct = [0u8; mlkem::CIPHERTEXT_BYTES];
        ct.copy_from_slice(&*core::ptr::addr_of!(CIPHERTEXT));
        let mut ss = [0u8; mlkem::SHARED_SECRET_BYTES];
        mlkem::decaps(&sk, &ct, &mut ss);
        SHARED_SECRET = ss;
    }
    0
}

#[no_mangle]
pub extern "C" fn photon_sha3_256() -> i32 {
    unsafe {
        let input = core::slice::from_raw_parts(core::ptr::addr_of!(INPUT) as *const u8, INPUT_LEN);
        let mut digest = [0u8; 32];
        keccak::sha3_256(input, &mut digest);
        DIGEST = digest;
    }
    0
}

#[no_mangle]
pub extern "C" fn photon_version() -> u32 {
    0x0001_0000
}
