//! clasp_photon_core — native post-quantum core.
//!
//! Zero external crates, `no_std`. The crate targets:
//!   - native rlib with C ABI exports below
//!   - wasm32-unknown-unknown via the separate `clasp_photon_wasm` cdylib
//!   - bare metal (no OS, no allocator, no panics in normal operation)
//!
//! NOTE: this is a clean-room baseline, not FIPS 203 validated. See README.

#![cfg_attr(not(test), no_std)]

pub mod keccak;
pub mod mlkem;
pub mod poly;

use core::slice;

/// C ABI: deterministic keygen.
///
/// # Safety
/// `seed`, `z`, `pk`, `sk` must point to buffers of 32, 32, 1184 and 2400
/// bytes respectively.
#[no_mangle]
pub unsafe extern "C" fn clasp_photon_keygen(
    seed: *const u8,
    z: *const u8,
    pk: *mut u8,
    sk: *mut u8,
) -> i32 {
    if seed.is_null() || z.is_null() || pk.is_null() || sk.is_null() {
        return -1;
    }
    let seed_arr: &[u8; 32] = slice::from_raw_parts(seed, 32).try_into().unwrap();
    let z_arr: &[u8; 32] = slice::from_raw_parts(z, 32).try_into().unwrap();
    let pk_buf = slice::from_raw_parts_mut(pk, mlkem::PUBLIC_KEY_BYTES);
    let sk_buf = slice::from_raw_parts_mut(sk, mlkem::SECRET_KEY_BYTES);
    let mut pk_out = [0u8; mlkem::PUBLIC_KEY_BYTES];
    let mut sk_out = [0u8; mlkem::SECRET_KEY_BYTES];
    mlkem::keygen(seed_arr, z_arr, &mut pk_out, &mut sk_out);
    pk_buf.copy_from_slice(&pk_out);
    sk_buf.copy_from_slice(&sk_out);
    0
}

/// C ABI: encapsulation with caller-supplied randomness.
///
/// # Safety
/// `pk`, `randomness`, `ct`, `ss` must point to buffers of 1184, 32, 1088 and
/// 32 bytes respectively.
#[no_mangle]
pub unsafe extern "C" fn clasp_photon_encaps(
    pk: *const u8,
    randomness: *const u8,
    ct: *mut u8,
    ss: *mut u8,
) -> i32 {
    if pk.is_null() || randomness.is_null() || ct.is_null() || ss.is_null() {
        return -1;
    }
    let pk_arr: &[u8; mlkem::PUBLIC_KEY_BYTES] =
        slice::from_raw_parts(pk, mlkem::PUBLIC_KEY_BYTES).try_into().unwrap();
    let rand_arr: &[u8; 32] = slice::from_raw_parts(randomness, 32).try_into().unwrap();
    let ct_buf = slice::from_raw_parts_mut(ct, mlkem::CIPHERTEXT_BYTES);
    let ss_buf = slice::from_raw_parts_mut(ss, mlkem::SHARED_SECRET_BYTES);
    let mut ct_out = [0u8; mlkem::CIPHERTEXT_BYTES];
    let mut ss_out = [0u8; mlkem::SHARED_SECRET_BYTES];
    mlkem::encaps(pk_arr, rand_arr, &mut ct_out, &mut ss_out);
    ct_buf.copy_from_slice(&ct_out);
    ss_buf.copy_from_slice(&ss_out);
    0
}

/// C ABI: decapsulation.
///
/// # Safety
/// `sk`, `ct`, `ss` must point to buffers of 2400, 1088 and 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn clasp_photon_decaps(
    sk: *const u8,
    ct: *const u8,
    ss: *mut u8,
) -> i32 {
    if sk.is_null() || ct.is_null() || ss.is_null() {
        return -1;
    }
    let sk_arr: &[u8; mlkem::SECRET_KEY_BYTES] =
        slice::from_raw_parts(sk, mlkem::SECRET_KEY_BYTES).try_into().unwrap();
    let ct_arr: &[u8; mlkem::CIPHERTEXT_BYTES] =
        slice::from_raw_parts(ct, mlkem::CIPHERTEXT_BYTES).try_into().unwrap();
    let ss_buf = slice::from_raw_parts_mut(ss, mlkem::SHARED_SECRET_BYTES);
    let mut ss_out = [0u8; mlkem::SHARED_SECRET_BYTES];
    mlkem::decaps(sk_arr, ct_arr, &mut ss_out);
    ss_buf.copy_from_slice(&ss_out);
    0
}

/// C ABI: SHA3-256.
///
/// # Safety
/// `data` must point to `len` readable bytes; `out` to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn clasp_photon_sha3_256(data: *const u8, len: usize, out: *mut u8) -> i32 {
    if out.is_null() || (data.is_null() && len != 0) {
        return -1;
    }
    let input = slice::from_raw_parts(data, len);
    let mut digest = [0u8; 32];
    keccak::sha3_256(input, &mut digest);
    slice::from_raw_parts_mut(out, 32).copy_from_slice(&digest);
    0
}

/// C ABI: forward NTT on 256 i32 coefficients (q = 3329).
///
/// # Safety
/// `coeffs` must point to 256 writable i32 values.
#[no_mangle]
pub unsafe extern "C" fn clasp_photon_ntt(coeffs: *mut i32) -> i32 {
    if coeffs.is_null() {
        return -1;
    }
    let poly: &mut [i32; poly::N] = &mut *(coeffs as *mut [i32; poly::N]);
    poly::ntt(poly);
    0
}

/// C ABI: inverse NTT on 256 i32 coefficients (q = 3329).
///
/// # Safety
/// `coeffs` must point to 256 writable i32 values.
#[no_mangle]
pub unsafe extern "C" fn clasp_photon_inv_ntt(coeffs: *mut i32) -> i32 {
    if coeffs.is_null() {
        return -1;
    }
    let poly: &mut [i32; poly::N] = &mut *(coeffs as *mut [i32; poly::N]);
    poly::inv_ntt(poly);
    0
}

/// C ABI: library version (single u32: major << 16 | minor << 8 | patch).
#[no_mangle]
pub extern "C" fn clasp_photon_version() -> u32 {
    0x0001_0000
}
