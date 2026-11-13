/**
 * Keccak / SHA-3 / SHAKE — zero-dependency implementation.
 *
 * Implements Keccak-f[1600] over 64-bit lanes using BigInt, plus the sponge
 * constructions required by the ML-KEM (Kyber) style Module-LWE KEM:
 *
 *   - SHA3-256   (H)   — rate 136, domain 0x06
 *   - SHA3-512   (G)   — rate 72,  domain 0x06
 *   - SHAKE128   (XOF) — rate 168, domain 0x1f
 *   - SHAKE256   (KDF / PRF) — rate 136, domain 0x1f
 *
 * No external dependencies. This is not the fastest Keccak available; it is a
 * portable reference implementation intended to be replaced by the native core
 * (see native/) on performance-critical targets.
 */

const MASK64 = (1n << 64n) - 1n;

const ROUND_CONSTANTS: readonly bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// Rotation offsets indexed as ROTATION[x + 5*y].
const ROTATION: readonly number[] = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];

function rotl64(value: bigint, shift: number): bigint {
  if (shift === 0) return value;
  const s = BigInt(shift);
  return ((value << s) | (value >> (64n - s))) & MASK64;
}

/** Keccak-f[1600] permutation, in place. State is 25 lanes (x + 5*y). */
export function keccakF1600(state: bigint[]): void {
  const c = new Array<bigint>(5);
  const b = new Array<bigint>(25);

  for (let round = 0; round < 24; round++) {
    // theta
    for (let x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
      for (let y = 0; y < 25; y += 5) {
        state[x + y] = (state[x + y] ^ d) & MASK64;
      }
    }

    // rho + pi
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const target = y + 5 * ((2 * x + 3 * y) % 5);
        b[target] = rotl64(state[x + 5 * y], ROTATION[x + 5 * y]);
      }
    }

    // chi
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x++) {
        state[x + y] =
          b[x + y] ^ ((~b[((x + 1) % 5) + y] & MASK64) & b[((x + 2) % 5) + y]);
      }
    }

    // iota
    state[0] = (state[0] ^ ROUND_CONSTANTS[round]) & MASK64;
  }
}

function xorByte(state: bigint[], index: number, byte: number): void {
  const lane = index >> 3;
  const shift = BigInt((index & 7) * 8);
  state[lane] = (state[lane] ^ (BigInt(byte) << shift)) & MASK64;
}

function stateByte(state: bigint[], index: number): number {
  const lane = index >> 3;
  const shift = BigInt((index & 7) * 8);
  return Number((state[lane] >> shift) & 0xffn);
}

/**
 * Generic Keccak sponge.
 *
 * @param rateBytes  Rate in bytes (168 for SHAKE128, 136 for SHA3-256/SHAKE256,
 *                   72 for SHA3-512).
 * @param domain     Domain separation byte (0x06 for SHA-3, 0x1f for SHAKE).
 * @param input      Input bytes.
 * @param outLen     Number of output bytes to squeeze.
 */
export function keccakSponge(
  rateBytes: number,
  domain: number,
  input: Uint8Array,
  outLen: number
): Uint8Array {
  const state = new Array<bigint>(25).fill(0n);

  let offset = 0;
  while (input.length - offset >= rateBytes) {
    for (let i = 0; i < rateBytes; i++) {
      xorByte(state, i, input[offset + i]);
    }
    keccakF1600(state);
    offset += rateBytes;
  }

  // Final (padded) block.
  const remaining = input.length - offset;
  for (let i = 0; i < remaining; i++) {
    xorByte(state, i, input[offset + i]);
  }
  xorByte(state, remaining, domain);
  xorByte(state, rateBytes - 1, 0x80);
  keccakF1600(state);

  const out = new Uint8Array(outLen);
  let produced = 0;
  while (produced < outLen) {
    const take = Math.min(rateBytes, outLen - produced);
    for (let i = 0; i < take; i++) {
      out[produced + i] = stateByte(state, i);
    }
    produced += take;
    if (produced < outLen) keccakF1600(state);
  }
  return out;
}

export function sha3_256(data: Uint8Array): Uint8Array {
  return keccakSponge(136, 0x06, data, 32);
}

export function sha3_512(data: Uint8Array): Uint8Array {
  return keccakSponge(72, 0x06, data, 64);
}

export function shake128(data: Uint8Array, outLen: number): Uint8Array {
  return keccakSponge(168, 0x1f, data, outLen);
}

export function shake256(data: Uint8Array, outLen: number): Uint8Array {
  return keccakSponge(136, 0x1f, data, outLen);
}

/** Concatenate byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Constant-time-ish byte comparison (length + XOR accumulation). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error('hex length must be even');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error('invalid hex');
    out[i] = byte;
  }
  return out;
}
