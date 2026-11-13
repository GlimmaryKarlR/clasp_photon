//! ML-KEM / Kyber-768 style Module-LWE KEM.
//!
//! Parameters: n = 256, q = 3329, k = 3, eta1 = eta2 = 2, du = 10, dv = 4.
//! Public key 1184 bytes, secret key 2400 bytes, ciphertext 1088 bytes,
//! shared secret 32 bytes.
//!
//! Clean-room baseline: same construction shape as Kyber (K-PKE + FO with
//! implicit rejection) but not FIPS 203 validated. See the repository README.

use crate::keccak::{sha3_256, sha3_512, shake128, shake256};
use crate::poly::*;

pub const K: usize = 3;
pub const PUBLIC_KEY_BYTES: usize = 1184;
pub const SECRET_KEY_BYTES: usize = 2400;
pub const CIPHERTEXT_BYTES: usize = 1088;
pub const SHARED_SECRET_BYTES: usize = 32;

type PolyVec = [[i32; N]; K];

fn prf(sigma: &[u8; 32], nonce: u8) -> [u8; 128] {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(sigma);
    input[32] = nonce;
    let mut out = [0u8; 128];
    shake256(&input, &mut out);
    out
}

/// SampleNTT(rho || col || row).
fn sample_ntt(rho: &[u8; 32], row: u8, col: u8) -> Poly {
    let mut input = [0u8; 34];
    input[..32].copy_from_slice(rho);
    input[32] = col;
    input[33] = row;
    let mut stream = [0u8; 6144];
    shake128(&input, &mut stream);

    let mut poly = [0i32; N];
    let mut count = 0usize;
    let mut i = 0usize;
    while i + 2 < stream.len() && count < N {
        let d1 = stream[i] as i32 | (((stream[i + 1] as i32) & 0x0f) << 8);
        let d2 = ((stream[i + 1] as i32) >> 4) | ((stream[i + 2] as i32) << 4);
        if d1 < Q {
            poly[count] = d1;
            count += 1;
        }
        if count < N && d2 < Q {
            poly[count] = d2;
            count += 1;
        }
        i += 3;
    }
    poly
}

fn sample_matrix(rho: &[u8; 32]) -> [[Poly; K]; K] {
    let mut matrix = [[[0i32; N]; K]; K];
    for i in 0..K {
        for j in 0..K {
            matrix[i][j] = sample_ntt(rho, i as u8, j as u8);
        }
    }
    matrix
}

fn kpke_keygen(
    rho: &[u8; 32],
    sigma: &[u8; 32],
    ek: &mut [u8; PUBLIC_KEY_BYTES],
    dk: &mut [u8; K * 384],
) {
    let matrix = sample_matrix(rho);

    let mut s_hat: PolyVec = [[0i32; N]; K];
    let mut e_hat: PolyVec = [[0i32; N]; K];
    for i in 0..K {
        let mut s = cbd2(&prf(sigma, i as u8));
        ntt(&mut s);
        s_hat[i] = s;
        let mut e = cbd2(&prf(sigma, (K + i) as u8));
        ntt(&mut e);
        e_hat[i] = e;
    }

    let mut t_hat: PolyVec = [[0i32; N]; K];
    for i in 0..K {
        let mut acc = [0i32; N];
        for j in 0..K {
            let product = pointwise_mul_ntt(&matrix[i][j], &s_hat[j]);
            acc = add_poly(&acc, &product);
        }
        t_hat[i] = add_poly(&acc, &e_hat[i]);
    }

    encode_vec12(&t_hat, &mut ek[..K * 384]);
    ek[K * 384..].copy_from_slice(rho);
    encode_vec12(&s_hat, dk);
}

fn kpke_encrypt(
    ek: &[u8; PUBLIC_KEY_BYTES],
    message: &[u8; 32],
    coins: &[u8; 32],
    ciphertext: &mut [u8; CIPHERTEXT_BYTES],
) {
    let mut t_hat: PolyVec = [[0i32; N]; K];
    decode_vec12(&ek[..K * 384], &mut t_hat);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[K * 384..K * 384 + 32]);
    let matrix = sample_matrix(&rho);

    let mut r_hat = cbd2(&prf(coins, 0));
    ntt(&mut r_hat);

    let mut e1: PolyVec = [[0i32; N]; K];
    for i in 0..K {
        e1[i] = cbd2(&prf(coins, (K + i) as u8));
    }
    let e2 = cbd2(&prf(coins, (2 * K) as u8));

    // u = A^T r + e1
    let mut u: PolyVec = [[0i32; N]; K];
    for i in 0..K {
        let mut acc = [0i32; N];
        for j in 0..K {
            let product = pointwise_mul_ntt(&matrix[j][i], &r_hat);
            acc = add_poly(&acc, &product);
        }
        let mut normal = acc;
        inv_ntt(&mut normal);
        u[i] = add_poly(&normal, &e1[i]);
    }

    // v = t^T r + e2 + m
    let mut acc = [0i32; N];
    for j in 0..K {
        let product = pointwise_mul_ntt(&t_hat[j], &r_hat);
        acc = add_poly(&acc, &product);
    }
    let mut normal = acc;
    inv_ntt(&mut normal);
    let v = add_poly(&add_poly(&normal, &e2), &message_to_poly(message));

    encode_vec_d(&u, 10, &mut ciphertext[..K * 320]);
    encode_vec_d(&[v], 4, &mut ciphertext[K * 320..]);
}

fn kpke_decrypt(
    dk: &[u8; K * 384],
    ciphertext: &[u8; CIPHERTEXT_BYTES],
    message: &mut [u8; 32],
) {
    let mut s_hat: PolyVec = [[0i32; N]; K];
    decode_vec12(dk, &mut s_hat);

    let mut u: PolyVec = [[0i32; N]; K];
    decode_vec_d(&ciphertext[..K * 320], 10, &mut u);
    let mut v_vec = [[0i32; N]; 1];
    decode_vec_d(&ciphertext[K * 320..], 4, &mut v_vec);

    let mut acc = [0i32; N];
    for i in 0..K {
        let mut u_hat = u[i];
        ntt(&mut u_hat);
        let product = pointwise_mul_ntt(&s_hat[i], &u_hat);
        acc = add_poly(&acc, &product);
    }
    let mut normal = acc;
    inv_ntt(&mut normal);
    let w = sub_poly(&v_vec[0], &normal);
    *message = poly_to_message(&w);
}

/// Generate a key pair from explicit seeds (deterministic / test mode).
pub fn keygen(
    seed: &[u8; 32],
    z: &[u8; 32],
    pk: &mut [u8; PUBLIC_KEY_BYTES],
    sk: &mut [u8; SECRET_KEY_BYTES],
) {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(seed);
    input[32] = K as u8;
    let mut g = [0u8; 64];
    sha3_512(&input, &mut g);

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    let mut sigma = [0u8; 32];
    sigma.copy_from_slice(&g[32..]);

    let mut ek = [0u8; PUBLIC_KEY_BYTES];
    let mut dk_pke = [0u8; K * 384];
    kpke_keygen(&rho, &sigma, &mut ek, &mut dk_pke);

    let mut h = [0u8; 32];
    sha3_256(&ek, &mut h);

    sk[..K * 384].copy_from_slice(&dk_pke);
    sk[K * 384..K * 384 + PUBLIC_KEY_BYTES].copy_from_slice(&ek);
    sk[K * 384 + PUBLIC_KEY_BYTES..K * 384 + PUBLIC_KEY_BYTES + 32].copy_from_slice(&h);
    sk[SECRET_KEY_BYTES - 32..].copy_from_slice(z);
    *pk = ek;
}

/// Deterministic keygen matching the TypeScript `mlkemKeygen(seed)` behaviour.
pub fn keygen_deterministic(
    seed: &[u8; 32],
    pk: &mut [u8; PUBLIC_KEY_BYTES],
    sk: &mut [u8; SECRET_KEY_BYTES],
) {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(seed);
    input[32] = 0x5a;
    let mut z = [0u8; 32];
    sha3_256(&input, &mut z);
    keygen(seed, &z, pk, sk);
}

/// Encapsulate with explicit 32-byte randomness.
pub fn encaps(
    pk: &[u8; PUBLIC_KEY_BYTES],
    randomness: &[u8; 32],
    ciphertext: &mut [u8; CIPHERTEXT_BYTES],
    shared_secret: &mut [u8; SHARED_SECRET_BYTES],
) {
    let mut message = [0u8; 32];
    sha3_256(randomness, &mut message);
    let mut pkh = [0u8; 32];
    sha3_256(pk, &mut pkh);

    let mut kr_input = [0u8; 64];
    kr_input[..32].copy_from_slice(&message);
    kr_input[32..].copy_from_slice(&pkh);
    let mut kr = [0u8; 64];
    sha3_512(&kr_input, &mut kr);

    let coins: &[u8; 32] = kr[32..].try_into().unwrap();
    kpke_encrypt(pk, &message, coins, ciphertext);

    let mut ct_hash = [0u8; 32];
    sha3_256(ciphertext, &mut ct_hash);
    let mut kdf_input = [0u8; 64];
    kdf_input[..32].copy_from_slice(&kr[..32]);
    kdf_input[32..].copy_from_slice(&ct_hash);
    shake256(&kdf_input, shared_secret);
}

/// Decapsulate. Corrupted ciphertexts take the implicit-rejection path.
pub fn decaps(
    sk: &[u8; SECRET_KEY_BYTES],
    ciphertext: &[u8; CIPHERTEXT_BYTES],
    shared_secret: &mut [u8; SHARED_SECRET_BYTES],
) {
    let dk_pke: &[u8; K * 384] = sk[..K * 384].try_into().unwrap();
    let ek: &[u8; PUBLIC_KEY_BYTES] =
        sk[K * 384..K * 384 + PUBLIC_KEY_BYTES].try_into().unwrap();
    let h: &[u8; 32] = sk[K * 384 + PUBLIC_KEY_BYTES..K * 384 + PUBLIC_KEY_BYTES + 32]
        .try_into()
        .unwrap();
    let z: &[u8; 32] = sk[SECRET_KEY_BYTES - 32..].try_into().unwrap();

    let mut message = [0u8; 32];
    kpke_decrypt(dk_pke, ciphertext, &mut message);

    let mut kr_input = [0u8; 64];
    kr_input[..32].copy_from_slice(&message);
    kr_input[32..].copy_from_slice(h);
    let mut kr = [0u8; 64];
    sha3_512(&kr_input, &mut kr);

    let mut reencrypted = [0u8; CIPHERTEXT_BYTES];
    let coins: &[u8; 32] = kr[32..].try_into().unwrap();
    kpke_encrypt(ek, &message, coins, &mut reencrypted);

    let mut ct_hash = [0u8; 32];
    sha3_256(ciphertext, &mut ct_hash);

    let matched = reencrypted == *ciphertext;
    let mut kdf_input = [0u8; 64];
    if matched {
        kdf_input[..32].copy_from_slice(&kr[..32]);
    } else {
        kdf_input[..32].copy_from_slice(z);
    }
    kdf_input[32..].copy_from_slice(&ct_hash);
    shake256(&kdf_input, shared_secret);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip() {
        let seed = [7u8; 32];
        let mut pk = [0u8; PUBLIC_KEY_BYTES];
        let mut sk = [0u8; SECRET_KEY_BYTES];
        keygen_deterministic(&seed, &mut pk, &mut sk);

        let mut ct = [0u8; CIPHERTEXT_BYTES];
        let mut ss = [0u8; SHARED_SECRET_BYTES];
        encaps(&pk, &[9u8; 32], &mut ct, &mut ss);

        let mut recovered = [0u8; SHARED_SECRET_BYTES];
        decaps(&sk, &ct, &mut recovered);
        assert_eq!(ss, recovered);

        // Tampering must not reveal the real secret.
        let mut tampered = ct;
        tampered[100] ^= 0x40;
        let mut rejected = [0u8; SHARED_SECRET_BYTES];
        decaps(&sk, &tampered, &mut rejected);
        assert_ne!(ss, rejected);
    }

    #[test]
    fn deterministic_keygen() {
        let mut pk1 = [0u8; PUBLIC_KEY_BYTES];
        let mut sk1 = [0u8; SECRET_KEY_BYTES];
        let mut pk2 = [0u8; PUBLIC_KEY_BYTES];
        let mut sk2 = [0u8; SECRET_KEY_BYTES];
        keygen_deterministic(&[3u8; 32], &mut pk1, &mut sk1);
        keygen_deterministic(&[3u8; 32], &mut pk2, &mut sk2);
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
    }
}
