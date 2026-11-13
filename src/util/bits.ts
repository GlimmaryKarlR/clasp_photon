/**
 * Bit and byte helpers shared by the optical and transport layers.
 *
 * QuaNet frames are defined in terms of individual bits (the spatial grid
 * carries three bits per cell, one per RGB channel) while carriers move
 * bytes. These helpers keep the conversion explicit and MSB-first.
 */

/** Expand bytes into an array of 0/1 bits, most-significant bit first. */
export function bytesToBits(bytes: Uint8Array): Uint8Array {
  const bits = new Uint8Array(bytes.length * 8);
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    for (let bit = 0; bit < 8; bit++) {
      bits[i * 8 + bit] = (byte >> (7 - bit)) & 1;
    }
  }
  return bits;
}

/** Pack 0/1 bits (MSB-first) into bytes. Trailing bits are zero-padded. */
export function bitsToBytes(bits: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) {
    if (bits[i] & 1) bytes[i >> 3] |= 1 << (7 - (i & 7));
  }
  return bytes;
}

/** Number of differing bits between two bit arrays (or byte prefix). */
export function countBitErrors(a: Uint8Array, b: Uint8Array): number {
  const length = Math.min(a.length, b.length);
  let errors = Math.abs(a.length - b.length) * 8;
  for (let i = 0; i < length; i++) {
    if (a[i] !== b[i]) errors += popcount8(a[i] ^ b[i]);
  }
  return errors;
}

function popcount8(value: number): number {
  let v = value & 0xff;
  v = v - ((v >> 1) & 0x55);
  v = (v & 0x33) + ((v >> 2) & 0x33);
  return (v + (v >> 4)) & 0x0f;
}

/** Concatenate byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Constant-time-ish byte equality for protocol checks. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Hex helpers used by tests and the CLI bridge. */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new Error('hex string must have even length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const value = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(value)) throw new Error('invalid hex string');
    out[i] = value;
  }
  return out;
}

/** Deterministic xorshift32 PRNG used by fixtures and code construction. */
export function xorshift32(seed: number): () => number {
  let state = seed >>> 0 || 0x1a2b3c4d;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state;
  };
}
