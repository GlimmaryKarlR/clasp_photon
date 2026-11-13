/**
 * ML-KEM / Kyber-768 style Module-LWE key encapsulation.
 *
 * Parameters match Kyber-768 / ML-KEM-768:
 *   n = 256, q = 3329, k = 3, eta1 = eta2 = 2, du = 10, dv = 4
 *   public key 1184 bytes, secret key 2400 bytes, ciphertext 1088 bytes,
 *   shared secret 32 bytes.
 *
 * Construction: IND-CPA K-PKE plus a Fujisaki-Okamoto transform with implicit
 * rejection (the same shape as Kyber). Hashes are SHA3-256/512 and SHAKE.
 *
 * IMPORTANT: this is a clean-room baseline, not FIPS 203 validated. It has not
 * been checked against official KATs and must not be described as certified
 * ML-KEM. See README caveats. The Rust core implements the same algorithms and
 * is cross-checked against this module.
 */

import {
  concatBytes,
  sha3_256,
  sha3_512,
  shake128,
  shake256,
  bytesEqual,
} from './keccak.js';
import {
  Q,
  N,
  type Poly,
  type PolyVec,
  addPoly,
  cbd2,
  decodeVec12,
  decodeVecD,
  encodeVec12,
  encodeVecD,
  invNtt,
  messageToPoly,
  ntt,
  pointwiseMulNtt,
  polyToMessage,
  subPoly,
} from './poly.js';

export const MLKEM_K = 3;
export const MLKEM_PUBLIC_KEY_BYTES = 1184;
export const MLKEM_SECRET_KEY_BYTES = 2400;
export const MLKEM_CIPHERTEXT_BYTES = 1088;
export const MLKEM_SHARED_SECRET_BYTES = 32;

export interface MlKemKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface MlKemEncapsulation {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

/** Cryptographically secure random bytes (Web Crypto / Node global crypto). */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  const webCrypto = globalThis.crypto;
  if (!webCrypto || typeof webCrypto.getRandomValues !== 'function') {
    throw new Error(
      'No CSPRNG available. Pass explicit randomness for deterministic tests.'
    );
  }
  webCrypto.getRandomValues(out);
  return out;
}

function prf(sigma: Uint8Array, nonce: number): Uint8Array {
  return shake256(concatBytes(sigma, new Uint8Array([nonce & 0xff])), 128);
}

/** Sample a uniform polynomial from SHAKE128(rho || col || row). */
function sampleNtt(rho: Uint8Array, row: number, col: number): Poly {
  const stream = shake128(
    concatBytes(rho, new Uint8Array([col & 0xff, row & 0xff])),
    6144
  );
  const poly = new Int32Array(N);
  let count = 0;
  for (let i = 0; i + 2 < stream.length && count < N; i += 3) {
    const d1 = stream[i] | ((stream[i + 1] & 0x0f) << 8);
    const d2 = (stream[i + 1] >> 4) | (stream[i + 2] << 4);
    if (d1 < Q) poly[count++] = d1;
    if (count < N && d2 < Q) poly[count++] = d2;
  }
  if (count < N) throw new Error('SHAKE128 rejection sampling exhausted');
  return poly;
}

/** A[i][j] = SampleNTT(rho || j || i). */
function sampleMatrix(rho: Uint8Array): PolyVec[] {
  const matrix: PolyVec[] = [];
  for (let i = 0; i < MLKEM_K; i++) {
    const row: PolyVec = [];
    for (let j = 0; j < MLKEM_K; j++) row.push(sampleNtt(rho, i, j));
    matrix.push(row);
  }
  return matrix;
}

/** Sum of NTT-domain products. */
function accumulateNtt(products: Poly[]): Poly {
  let acc: Poly = new Int32Array(N);
  for (const product of products) acc = addPoly(acc, product);
  return acc;
}

/** K-PKE key generation. Returns public key bytes (incl. rho) and secret key bytes. */
function kpkeKeygen(
  rho: Uint8Array,
  sigma: Uint8Array
): { ek: Uint8Array; dk: Uint8Array } {
  const matrix = sampleMatrix(rho);

  const sHat: PolyVec = [];
  const eHat: PolyVec = [];
  for (let i = 0; i < MLKEM_K; i++) {
    sHat.push(ntt(cbd2(prf(sigma, i))));
    eHat.push(ntt(cbd2(prf(sigma, MLKEM_K + i))));
  }

  const tHat: PolyVec = [];
  for (let i = 0; i < MLKEM_K; i++) {
    const products = matrix[i].map((a, j) => pointwiseMulNtt(a, sHat[j]));
    tHat.push(addPoly(accumulateNtt(products), eHat[i]));
  }

  const ek = new Uint8Array(MLKEM_PUBLIC_KEY_BYTES);
  ek.set(encodeVec12(tHat), 0);
  ek.set(rho, MLKEM_K * 384);
  return { ek, dk: encodeVec12(sHat) };
}

function kpkeEncrypt(
  ek: Uint8Array,
  message: Uint8Array,
  coins: Uint8Array
): Uint8Array {
  if (ek.length !== MLKEM_PUBLIC_KEY_BYTES) throw new Error('invalid public key length');
  const tHat = decodeVec12(ek.subarray(0, MLKEM_K * 384), MLKEM_K);
  const rho = ek.subarray(MLKEM_K * 384, MLKEM_K * 384 + 32);
  const matrix = sampleMatrix(rho); // A[i][j]

  const rHat = ntt(cbd2(prf(coins, 0)));
  const e1: PolyVec = [];
  const e2 = cbd2(prf(coins, 2 * MLKEM_K));
  for (let i = 0; i < MLKEM_K; i++) e1.push(cbd2(prf(coins, MLKEM_K + i)));

  // u = A^T r + e1
  const u: PolyVec = [];
  for (let i = 0; i < MLKEM_K; i++) {
    const products: Poly[] = [];
    for (let j = 0; j < MLKEM_K; j++) {
      // A^T[i][j] = A[j][i] = sampleNtt(rho, j, i)
      products.push(pointwiseMulNtt(matrix[j][i], rHat));
    }
    u.push(addPoly(invNtt(accumulateNtt(products)), e1[i]));
  }

  // v = t^T r + e2 + m
  const vProducts = tHat.map((t) => pointwiseMulNtt(t, rHat));
  const v = addPoly(
    addPoly(invNtt(accumulateNtt(vProducts)), e2),
    messageToPoly(message)
  );

  const c1 = encodeVecD(u, 10);
  const c2 = encodeVecD([v], 4);
  const ciphertext = new Uint8Array(MLKEM_CIPHERTEXT_BYTES);
  ciphertext.set(c1, 0);
  ciphertext.set(c2, c1.length);
  return ciphertext;
}

function kpkeDecrypt(dkPke: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  if (ciphertext.length !== MLKEM_CIPHERTEXT_BYTES) {
    throw new Error('invalid ciphertext length');
  }
  const sHat = decodeVec12(dkPke, MLKEM_K);
  const c1Len = MLKEM_K * 320;
  const u = decodeVecD(ciphertext.subarray(0, c1Len), MLKEM_K, 10);
  const v = decodeVecD(ciphertext.subarray(c1Len), 1, 4)[0];

  const products: Poly[] = [];
  for (let i = 0; i < MLKEM_K; i++) {
    products.push(pointwiseMulNtt(sHat[i], ntt(u[i])));
  }
  const messagePoly = subPoly(v, invNtt(accumulateNtt(products)));
  return polyToMessage(messagePoly);
}

/**
 * Generate an ML-KEM key pair.
 *
 * @param seed  Optional 32-byte deterministic seed (tests / reproducible setup).
 * @param zSeed Optional 32-byte implicit-rejection seed. When only `seed` is
 *              given, z is derived as SHA3-256(seed || 0x5a) so the whole key
 *              pair is reproducible for cross-language vectors.
 */
export function mlkemKeygen(seed?: Uint8Array, zSeed?: Uint8Array): MlKemKeyPair {
  const d = seed ?? randomBytes(32);
  if (d.length !== 32) throw new Error('keygen seed must be 32 bytes');

  const g = sha3_512(concatBytes(d, new Uint8Array([MLKEM_K])));
  const rho = g.subarray(0, 32);
  const sigma = g.subarray(32, 64);
  const { ek, dk } = kpkeKeygen(rho, sigma);

  const h = sha3_256(ek);
  const z =
    zSeed ??
    (seed
      ? sha3_256(concatBytes(seed, new Uint8Array([0x5a])))
      : randomBytes(32));
  if (z.length !== 32) throw new Error('z seed must be 32 bytes');
  const secretKey = new Uint8Array(MLKEM_SECRET_KEY_BYTES);
  secretKey.set(dk, 0);
  secretKey.set(ek, dk.length);
  secretKey.set(h, dk.length + ek.length);
  secretKey.set(z, dk.length + ek.length + 32);

  return { publicKey: ek, secretKey };
}

/**
 * Encapsulate a 32-byte shared secret to a public key.
 *
 * @param randomness Optional 32-byte seed (tests / deterministic vectors).
 */
export function mlkemEncapsulate(
  publicKey: Uint8Array,
  randomness?: Uint8Array
): MlKemEncapsulation {
  if (publicKey.length !== MLKEM_PUBLIC_KEY_BYTES) {
    throw new Error('invalid public key length');
  }
  const seed = randomness ?? randomBytes(32);
  const message = sha3_256(seed);
  const pkh = sha3_256(publicKey);
  const kr = sha3_512(concatBytes(message, pkh));
  const kBar = kr.subarray(0, 32);
  const coins = kr.subarray(32, 64);

  const ciphertext = kpkeEncrypt(publicKey, message, coins);
  const sharedSecret = shake256(concatBytes(kBar, sha3_256(ciphertext)), 32);
  return { ciphertext, sharedSecret };
}

/**
 * Decapsulate a ciphertext. Uses implicit rejection: a corrupted ciphertext
 * returns a deterministic pseudo-random secret instead of throwing, matching
 * the FO transform behaviour expected by higher layers.
 */
export function mlkemDecapsulate(
  secretKey: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array {
  if (secretKey.length !== MLKEM_SECRET_KEY_BYTES) {
    throw new Error('invalid secret key length');
  }
  const dkLen = MLKEM_K * 384;
  const dkPke = secretKey.subarray(0, dkLen);
  const ek = secretKey.subarray(dkLen, dkLen + MLKEM_PUBLIC_KEY_BYTES);
  const h = secretKey.subarray(
    dkLen + MLKEM_PUBLIC_KEY_BYTES,
    dkLen + MLKEM_PUBLIC_KEY_BYTES + 32
  );
  const z = secretKey.subarray(secretKey.length - 32);

  const message = kpkeDecrypt(dkPke, ciphertext);
  const kr = sha3_512(concatBytes(message, h));
  const kBar = kr.subarray(0, 32);
  const coins = kr.subarray(32, 64);
  const reencrypted = kpkeEncrypt(ek, message, coins);

  if (bytesEqual(reencrypted, ciphertext)) {
    return shake256(concatBytes(kBar, sha3_256(ciphertext)), 32);
  }
  return shake256(concatBytes(z, sha3_256(ciphertext)), 32);
}
