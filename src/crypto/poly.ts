/**
 * Polynomial arithmetic over R_q = Z_q[X] / (X^256 + 1), q = 3329.
 *
 * Baseline for the clasp_photon Module-LWE KEM (ML-KEM / Kyber-768
 * parameters). The same algorithms are implemented in the zero-dependency
 * Rust core under native/clasp_photon_core; this TypeScript version is the
 * portable reference used by browsers and as a cross-check for the native code.
 *
 * NTT layout follows the Kyber reference transform: 7 layers, 128 twiddles
 * generated as 17^bitrev7(i) mod q, base multiplication over degree-1 pairs.
 */

export const Q = 3329;
export const N = 256;

function mod(value: number): number {
  const r = value % Q;
  return r < 0 ? r + Q : r;
}

function modPow(base: number, exponent: number): number {
  let result = 1;
  let b = base % Q;
  let e = exponent;
  while (e > 0) {
    if (e & 1) result = (result * b) % Q;
    b = (b * b) % Q;
    e >>= 1;
  }
  return result;
}

function modInverse(value: number): number {
  let t = 0;
  let newT = 1;
  let r = Q;
  let newR = mod(value);
  while (newR !== 0) {
    const q = Math.floor(r / newR);
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  if (r !== 1) throw new Error('value is not invertible mod q');
  return mod(t);
}

function bitReverse7(value: number): number {
  let result = 0;
  for (let bit = 0; bit < 7; bit++) {
    result |= ((value >> bit) & 1) << (6 - bit);
  }
  return result;
}

/** 128 twiddle factors: zetas[i] = 17^bitrev7(i) mod q. */
export const ZETAS: readonly number[] = Array.from({ length: 128 }, (_, i) =>
  modPow(17, bitReverse7(i))
);

const INV_128 = modInverse(128);
const INV_256 = modInverse(256);

export type Poly = Int32Array;
export type PolyVec = Poly[];

export function zeroPoly(): Poly {
  return new Int32Array(N);
}

export function randomPoly(rand: () => number = Math.random): Poly {
  const p = new Int32Array(N);
  for (let i = 0; i < N; i++) p[i] = Math.floor(rand() * Q) % Q;
  return p;
}

export function addPoly(a: Poly, b: Poly): Poly {
  const out = new Int32Array(N);
  for (let i = 0; i < N; i++) out[i] = mod(a[i] + b[i]);
  return out;
}

export function subPoly(a: Poly, b: Poly): Poly {
  const out = new Int32Array(N);
  for (let i = 0; i < N; i++) out[i] = mod(a[i] - b[i]);
  return out;
}

export function copyPoly(a: Poly): Poly {
  return new Int32Array(a);
}

/** Forward NTT, in place. */
export function ntt(a: Poly): Poly {
  const r = a instanceof Int32Array ? copyPoly(a) : new Int32Array(a);
  let k = 1;
  for (let len = 128; len >= 2; len >>= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      const zeta = ZETAS[k++];
      for (let j = start; j < start + len; j++) {
        const t = (zeta * r[j + len]) % Q;
        const lo = r[j] - t;
        r[j + len] = lo < 0 ? lo + Q : lo;
        const hi = r[j] + t;
        r[j] = hi >= Q ? hi - Q : hi;
      }
    }
  }
  return r;
}

/** Inverse NTT, in place. */
export function invNtt(a: Poly): Poly {
  const r = copyPoly(a);
  let k = 127;
  for (let len = 2; len <= 128; len <<= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      const zeta = (Q - ZETAS[k--]) % Q;
      for (let j = start; j < start + len; j++) {
        const t = r[j];
        const sum = t + r[j + len];
        r[j] = sum >= Q ? sum - Q : sum;
        let diff = t - r[j + len];
        if (diff < 0) diff += Q;
        r[j + len] = (zeta * diff) % Q;
      }
    }
  }
  for (let i = 0; i < N; i++) r[i] = (r[i] * INV_128) % Q;
  return r;
}

function basemul(a0: number, a1: number, b0: number, b1: number, zeta: number): [number, number] {
  return [
    (a0 * b0 + ((zeta * a1 * b1) % Q)) % Q,
    (a0 * b1 + a1 * b0) % Q,
  ];
}

/** Pointwise multiplication of two NTT-domain polynomials (stays in NTT domain). */
export function pointwiseMulNtt(a: Poly, b: Poly): Poly {
  const r = new Int32Array(N);
  for (let i = 0; i < 64; i++) {
    const zeta = ZETAS[64 + i];
    const [r0, r1] = basemul(a[4 * i], a[4 * i + 1], b[4 * i], b[4 * i + 1], zeta);
    r[4 * i] = r0;
    r[4 * i + 1] = r1;

    const negZeta = (Q - zeta) % Q;
    const [r2, r3] = basemul(a[4 * i + 2], a[4 * i + 3], b[4 * i + 2], b[4 * i + 3], negZeta);
    r[4 * i + 2] = r2;
    r[4 * i + 3] = r3;
  }
  return r;
}

/** Negacyclic polynomial multiplication: invNTT(ntt(a) ∘ ntt(b)). */
export function mulPoly(a: Poly, b: Poly): Poly {
  return invNtt(pointwiseMulNtt(ntt(a), ntt(b)));
}

/** Schoolbook negacyclic multiplication — reference implementation for tests. */
export function schoolbookMul(a: Poly, b: Poly): Poly {
  const r = new Int32Array(N);
  for (let i = 0; i < N; i++) {
    for (let j = 0; j < N; j++) {
      const product = (a[i] * b[j]) % Q;
      const index = i + j;
      if (index < N) {
        r[index] = (r[index] + product) % Q;
      } else {
        r[index - N] = mod(r[index - N] - product);
      }
    }
  }
  return r;
}

/** Centered binomial distribution, eta = 2, from 128 bytes. */
export function cbd2(bytes: Uint8Array): Poly {
  if (bytes.length < 128) throw new Error('CBD(2) needs 128 bytes');
  const poly = new Int32Array(N);
  for (let i = 0; i < N / 8; i++) {
    const t =
      bytes[4 * i] |
      (bytes[4 * i + 1] << 8) |
      (bytes[4 * i + 2] << 16) |
      (bytes[4 * i + 3] << 24);
    let d = t & 0x55555555;
    d += (t >>> 1) & 0x55555555;
    for (let j = 0; j < 8; j++) {
      const a = (d >>> (4 * j)) & 3;
      const b = (d >>> (4 * j + 2)) & 3;
      poly[8 * i + j] = a - b;
    }
  }
  for (let i = 0; i < N; i++) {
    if (poly[i] < 0) poly[i] += Q;
  }
  return poly;
}

/** Round-to-nearest compression to d bits. */
export function compressCoeff(value: number, d: number): number {
  const scale = 1 << d;
  return Math.floor((value * scale + Q / 2) / Q) & (scale - 1);
}

/** Round-to-nearest decompression from d bits. */
export function decompressCoeff(value: number, d: number): number {
  const scale = 1 << d;
  return Math.floor((value * Q + scale / 2) / scale);
}

/** Pack 256 12-bit coefficients into 384 bytes (t and s encoding). */
export function encodePoly12(poly: Poly): Uint8Array {
  const out = new Uint8Array(384);
  let acc = 0;
  let bits = 0;
  let index = 0;
  for (let i = 0; i < N; i++) {
    acc |= (mod(poly[i]) & 0xfff) << bits;
    bits += 12;
    while (bits >= 8) {
      out[index++] = acc & 0xff;
      acc >>>= 8;
      bits -= 8;
    }
  }
  return out;
}

export function decodePoly12(bytes: Uint8Array): Poly {
  if (bytes.length < 384) throw new Error('12-bit poly needs 384 bytes');
  const poly = new Int32Array(N);
  let acc = 0;
  let bits = 0;
  let index = 0;
  for (let i = 0; i < N; i++) {
    while (bits < 12) {
      acc |= bytes[index++] << bits;
      bits += 8;
    }
    poly[i] = acc & 0xfff;
    acc >>>= 12;
    bits -= 12;
  }
  return poly;
}

/** Pack 256 d-bit compressed coefficients. */
export function encodePolyD(poly: Poly, d: number): Uint8Array {
  const outLen = (N * d) / 8;
  const out = new Uint8Array(outLen);
  let acc = 0;
  let bits = 0;
  let index = 0;
  for (let i = 0; i < N; i++) {
    acc |= compressCoeff(mod(poly[i]), d) << bits;
    bits += d;
    while (bits >= 8) {
      out[index++] = acc & 0xff;
      acc >>>= 8;
      bits -= 8;
    }
  }
  return out;
}

export function decodePolyD(bytes: Uint8Array, d: number): Poly {
  const outLen = (N * d) / 8;
  if (bytes.length < outLen) throw new Error(`${d}-bit poly needs ${outLen} bytes`);
  const poly = new Int32Array(N);
  let acc = 0;
  let bits = 0;
  let index = 0;
  for (let i = 0; i < N; i++) {
    while (bits < d) {
      acc |= bytes[index++] << bits;
      bits += 8;
    }
    poly[i] = decompressCoeff(acc & ((1 << d) - 1), d);
    acc >>>= d;
    bits -= d;
  }
  return poly;
}

export function encodeVec12(vec: PolyVec): Uint8Array {
  const out = new Uint8Array(vec.length * 384);
  vec.forEach((p, i) => out.set(encodePoly12(p), i * 384));
  return out;
}

export function decodeVec12(bytes: Uint8Array, k: number): PolyVec {
  const vec: PolyVec = [];
  for (let i = 0; i < k; i++) {
    vec.push(decodePoly12(bytes.subarray(i * 384, (i + 1) * 384)));
  }
  return vec;
}

export function encodeVecD(vec: PolyVec, d: number): Uint8Array {
  const per = (N * d) / 8;
  const out = new Uint8Array(vec.length * per);
  vec.forEach((p, i) => out.set(encodePolyD(p, d), i * per));
  return out;
}

export function decodeVecD(bytes: Uint8Array, k: number, d: number): PolyVec {
  const per = (N * d) / 8;
  const vec: PolyVec = [];
  for (let i = 0; i < k; i++) {
    vec.push(decodePolyD(bytes.subarray(i * per, (i + 1) * per), d));
  }
  return vec;
}

/** Convert 32 message bytes to a 256-coefficient message polynomial (d = 1). */
export function messageToPoly(message: Uint8Array): Poly {
  if (message.length !== 32) throw new Error('message must be 32 bytes');
  const poly = new Int32Array(N);
  for (let i = 0; i < N; i++) {
    const bit = (message[i >> 3] >> (i & 7)) & 1;
    poly[i] = decompressCoeff(bit, 1);
  }
  return poly;
}

/** Convert a message polynomial back to 32 bytes (d = 1). */
export function polyToMessage(poly: Poly): Uint8Array {
  const message = new Uint8Array(32);
  for (let i = 0; i < N; i++) {
    const bit = compressCoeff(mod(poly[i]), 1);
    if (bit) message[i >> 3] |= 1 << (i & 7);
  }
  return message;
}

/** Multiply by the inverse of 256 (exposed for the native cross-check). */
export const INV_256_MOD_Q = INV_256;
