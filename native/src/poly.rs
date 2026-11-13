//! Polynomial arithmetic over R_q = Z_q[X]/(X^256 + 1), q = 3329.
//!
//! Same transform layout as the TypeScript reference: zetas[i] = 17^bitrev7(i)
//! mod q, seven Cooley-Tukey layers, base multiplication over degree-1 pairs.
//! Written without allocation so it runs on bare metal and wasm32-unknown.

pub const Q: i32 = 3329;
pub const N: usize = 256;
pub type Poly = [i32; N];

const fn mod_pow(mut base: i64, mut exp: u32, modulus: i64) -> i32 {
    let mut result = 1i64;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exp >>= 1;
    }
    result as i32
}

const fn bitrev7(value: u32) -> u32 {
    let mut result = 0u32;
    let mut bit = 0u32;
    while bit < 7 {
        result |= ((value >> bit) & 1) << (6 - bit);
        bit += 1;
    }
    result
}

const fn build_zetas() -> [i32; 128] {
    let mut zetas = [0i32; 128];
    let mut i = 0usize;
    while i < 128 {
        zetas[i] = mod_pow(17, bitrev7(i as u32), Q as i64);
        i += 1;
    }
    zetas
}

pub const ZETAS: [i32; 128] = build_zetas();

const INV_128: i32 = 3303; // 128^-1 mod 3329
const INV_256: i32 = 3303 * 2 % Q; // exposed for cross-checks

pub fn mod_q(value: i32) -> i32 {
    let r = value % Q;
    if r < 0 {
        r + Q
    } else {
        r
    }
}

pub fn add_poly(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0i32; N];
    let mut i = 0usize;
    while i < N {
        out[i] = mod_q(a[i] + b[i]);
        i += 1;
    }
    out
}

pub fn sub_poly(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0i32; N];
    let mut i = 0usize;
    while i < N {
        out[i] = mod_q(a[i] - b[i]);
        i += 1;
    }
    out
}

/// Forward NTT, in place.
pub fn ntt(a: &mut Poly) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k] as i64;
            k += 1;
            let mut j = start;
            while j < start + len {
                let t = (zeta * a[j + len] as i64 % Q as i64) as i32;
                a[j + len] = mod_q(a[j] - t);
                a[j] = mod_q(a[j] + t);
                j += 1;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT, in place.
pub fn inv_ntt(a: &mut Poly) {
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = mod_q(Q - ZETAS[k]);
            k = k.wrapping_sub(1);
            let mut j = start;
            while j < start + len {
                let t = a[j];
                a[j] = mod_q(t + a[j + len]);
                let diff = mod_q(t - a[j + len]);
                a[j + len] = (zeta as i64 * diff as i64 % Q as i64) as i32;
                j += 1;
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    let mut i = 0usize;
    while i < N {
        a[i] = (a[i] as i64 * INV_128 as i64 % Q as i64) as i32;
        i += 1;
    }
}

fn basemul(a0: i32, a1: i32, b0: i32, b1: i32, zeta: i32) -> (i32, i32) {
    let r0 = ((a0 as i64 * b0 as i64) % Q as i64
        + (zeta as i64 * a1 as i64 % Q as i64) * b1 as i64 % Q as i64)
        % Q as i64;
    let r1 = ((a0 as i64 * b1 as i64) % Q as i64 + (a1 as i64 * b0 as i64) % Q as i64)
        % Q as i64;
    (r0 as i32, r1 as i32)
}

/// Pointwise multiplication of two NTT-domain polynomials.
pub fn pointwise_mul_ntt(a: &Poly, b: &Poly) -> Poly {
    let mut r = [0i32; N];
    let mut i = 0usize;
    while i < 64 {
        let zeta = ZETAS[64 + i];
        let (r0, r1) = basemul(a[4 * i], a[4 * i + 1], b[4 * i], b[4 * i + 1], zeta);
        r[4 * i] = r0;
        r[4 * i + 1] = r1;
        let neg_zeta = mod_q(Q - zeta);
        let (r2, r3) = basemul(
            a[4 * i + 2],
            a[4 * i + 3],
            b[4 * i + 2],
            b[4 * i + 3],
            neg_zeta,
        );
        r[4 * i + 2] = r2;
        r[4 * i + 3] = r3;
        i += 1;
    }
    r
}

pub fn mul_poly(a: &Poly, b: &Poly) -> Poly {
    let mut ah = *a;
    let mut bh = *b;
    ntt(&mut ah);
    ntt(&mut bh);
    let mut product = pointwise_mul_ntt(&ah, &bh);
    inv_ntt(&mut product);
    product
}

/// Schoolbook negacyclic multiplication — reference for tests.
pub fn schoolbook_mul(a: &Poly, b: &Poly) -> Poly {
    let mut r = [0i32; N];
    let mut i = 0usize;
    while i < N {
        let mut j = 0usize;
        while j < N {
            let product = (a[i] as i64 * b[j] as i64 % Q as i64) as i32;
            let index = i + j;
            if index < N {
                r[index] = mod_q(r[index] + product);
            } else {
                r[index - N] = mod_q(r[index - N] - product);
            }
            j += 1;
        }
        i += 1;
    }
    r
}

/// Centered binomial distribution, eta = 2, from 128 bytes.
pub fn cbd2(bytes: &[u8; 128]) -> Poly {
    let mut poly = [0i32; N];
    let mut i = 0usize;
    while i < N / 8 {
        let t = (bytes[4 * i] as u32)
            | ((bytes[4 * i + 1] as u32) << 8)
            | ((bytes[4 * i + 2] as u32) << 16)
            | ((bytes[4 * i + 3] as u32) << 24);
        let mut d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;
        let mut j = 0usize;
        while j < 8 {
            let a = (d >> (4 * j)) & 3;
            let b = (d >> (4 * j + 2)) & 3;
            poly[8 * i + j] = a as i32 - b as i32;
            j += 1;
        }
        i += 1;
    }
    let mut i = 0usize;
    while i < N {
        if poly[i] < 0 {
            poly[i] += Q;
        }
        i += 1;
    }
    poly
}

pub fn compress_coeff(value: i32, d: usize) -> i32 {
    let scale = 1i64 << d;
    (((value as i64 * scale + (Q as i64) / 2) / Q as i64) & (scale - 1)) as i32
}

pub fn decompress_coeff(value: i32, d: usize) -> i32 {
    let scale = 1i64 << d;
    ((value as i64 * Q as i64 + scale / 2) / scale) as i32
}

pub fn encode_poly12(poly: &Poly, out: &mut [u8]) {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut index = 0usize;
    let mut i = 0usize;
    while i < N {
        acc |= ((mod_q(poly[i]) as u32) & 0x0fff) << bits;
        bits += 12;
        while bits >= 8 {
            out[index] = (acc & 0xff) as u8;
            index += 1;
            acc >>= 8;
            bits -= 8;
        }
        i += 1;
    }
}

pub fn decode_poly12(bytes: &[u8], poly: &mut Poly) {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut index = 0usize;
    let mut i = 0usize;
    while i < N {
        while bits < 12 {
            acc |= (bytes[index] as u32) << bits;
            index += 1;
            bits += 8;
        }
        poly[i] = (acc & 0x0fff) as i32;
        acc >>= 12;
        bits -= 12;
        i += 1;
    }
}

pub fn encode_poly_d(poly: &Poly, d: usize, out: &mut [u8]) {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut index = 0usize;
    let mut i = 0usize;
    while i < N {
        acc |= (compress_coeff(mod_q(poly[i]), d) as u32) << bits;
        bits += d as u32;
        while bits >= 8 {
            out[index] = (acc & 0xff) as u8;
            index += 1;
            acc >>= 8;
            bits -= 8;
        }
        i += 1;
    }
}

pub fn decode_poly_d(bytes: &[u8], d: usize, poly: &mut Poly) {
    let mask = (1u32 << d) - 1;
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut index = 0usize;
    let mut i = 0usize;
    while i < N {
        while bits < d as u32 {
            acc |= (bytes[index] as u32) << bits;
            index += 1;
            bits += 8;
        }
        poly[i] = decompress_coeff((acc & mask) as i32, d);
        acc >>= d;
        bits -= d as u32;
        i += 1;
    }
}

pub fn encode_vec12<const K: usize>(vec: &[[i32; N]; K], out: &mut [u8]) {
    let mut i = 0usize;
    while i < K {
        encode_poly12(&vec[i], &mut out[i * 384..(i + 1) * 384]);
        i += 1;
    }
}

pub fn decode_vec12<const K: usize>(bytes: &[u8], vec: &mut [[i32; N]; K]) {
    let mut i = 0usize;
    while i < K {
        decode_poly12(&bytes[i * 384..(i + 1) * 384], &mut vec[i]);
        i += 1;
    }
}

pub fn encode_vec_d<const K: usize>(vec: &[[i32; N]; K], d: usize, out: &mut [u8]) {
    let per = N * d / 8;
    let mut i = 0usize;
    while i < K {
        encode_poly_d(&vec[i], d, &mut out[i * per..(i + 1) * per]);
        i += 1;
    }
}

pub fn decode_vec_d<const K: usize>(bytes: &[u8], d: usize, vec: &mut [[i32; N]; K]) {
    let per = N * d / 8;
    let mut i = 0usize;
    while i < K {
        decode_poly_d(&bytes[i * per..(i + 1) * per], d, &mut vec[i]);
        i += 1;
    }
}

pub fn message_to_poly(message: &[u8; 32]) -> Poly {
    let mut poly = [0i32; N];
    let mut i = 0usize;
    while i < N {
        let bit = (message[i >> 3] >> (i & 7)) & 1;
        poly[i] = decompress_coeff(bit as i32, 1);
        i += 1;
    }
    poly
}

pub fn poly_to_message(poly: &Poly) -> [u8; 32] {
    let mut message = [0u8; 32];
    let mut i = 0usize;
    while i < N {
        if compress_coeff(mod_q(poly[i]), 1) != 0 {
            message[i >> 3] |= 1 << (i & 7);
        }
        i += 1;
    }
    message
}

/// Inverse of 256 mod q, exported for the cross-language check.
pub const INV_256_MOD_Q: i32 = INV_256;

#[cfg(test)]
mod tests {
    use super::*;

    fn lcg(seed: &mut u32) -> i32 {
        *seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        ((*seed >> 16) as i32) % Q
    }

    #[test]
    fn ntt_matches_schoolbook() {
        let mut seed = 123456789u32;
        let mut a = [0i32; N];
        let mut b = [0i32; N];
        for i in 0..N {
            a[i] = lcg(&mut seed).abs();
            b[i] = lcg(&mut seed).abs();
        }
        assert_eq!(mul_poly(&a, &b), schoolbook_mul(&a, &b));
    }

    #[test]
    fn ntt_roundtrip() {
        let mut seed = 42u32;
        let mut a = [0i32; N];
        for i in 0..N {
            a[i] = lcg(&mut seed).abs();
        }
        let mut transformed = a;
        ntt(&mut transformed);
        inv_ntt(&mut transformed);
        assert_eq!(a, transformed);
    }

    #[test]
    fn poly_encoding_roundtrip() {
        let mut a = [0i32; N];
        for i in 0..N {
            a[i] = (i as i32 * 13) % Q;
        }
        let mut bytes = [0u8; 384];
        encode_poly12(&a, &mut bytes);
        let mut decoded = [0i32; N];
        decode_poly12(&bytes, &mut decoded);
        assert_eq!(a, decoded);

        let mut packed = [0u8; 320];
        encode_poly_d(&a, 10, &mut packed);
        let mut unpacked = [0i32; N];
        decode_poly_d(&packed, 10, &mut unpacked);
        for i in 0..N {
            assert!((a[i] - unpacked[i]).abs() <= 2);
        }
    }
}
