/**
 * ChaCha20-Poly1305 AEAD (RFC 8439) — zero-dependency implementation.
 *
 * Used as the payload-encryption layer above the ML-KEM style handshake.
 * Poly1305 uses BigInt for the 130-bit accumulator: simple and auditable,
 * slower than limb-based code. A native implementation is planned for
 * throughput-sensitive paths.
 */

const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

function rotl32(v: number, n: number): number {
  return ((v << n) | (v >>> (32 - n))) >>> 0;
}

function quarterRound(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl32(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl32(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl32(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl32(s[b] ^ s[c], 7);
}

function readU32LE(bytes: Uint8Array, offset: number): number {
  return (
    (bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)) >>>
    0
  );
}

function writeU32LE(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

/** Produce one 64-byte ChaCha20 keystream block. */
export function chacha20Block(key: Uint8Array, nonce: Uint8Array, counter: number): Uint8Array {
  if (key.length !== 32) throw new Error('ChaCha20 key must be 32 bytes');
  if (nonce.length !== 12) throw new Error('ChaCha20 nonce must be 12 bytes');

  const state = new Uint32Array(16);
  state.set(SIGMA, 0);
  for (let i = 0; i < 8; i++) state[4 + i] = readU32LE(key, i * 4);
  state[12] = counter >>> 0;
  for (let i = 0; i < 3; i++) state[13 + i] = readU32LE(nonce, i * 4);

  const working = new Uint32Array(state);
  for (let i = 0; i < 10; i++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }

  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    writeU32LE(out, i * 4, (working[i] + state[i]) >>> 0);
  }
  return out;
}

/** XOR `data` with the ChaCha20 keystream starting at `counter`. */
export function chacha20Xor(
  key: Uint8Array,
  nonce: Uint8Array,
  counter: number,
  data: Uint8Array
): Uint8Array {
  const out = new Uint8Array(data.length);
  let blockCounter = counter >>> 0;
  for (let offset = 0; offset < data.length; offset += 64) {
    const block = chacha20Block(key, nonce, blockCounter++);
    const take = Math.min(64, data.length - offset);
    for (let i = 0; i < take; i++) {
      out[offset + i] = data[offset + i] ^ block[i];
    }
  }
  return out;
}

const P1305 = (1n << 130n) - 5n;
const MASK128 = (1n << 128n) - 1n;
const R_CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffffn;

function leToBigInt(bytes: Uint8Array, start = 0, end = bytes.length): bigint {
  let value = 0n;
  for (let i = end - 1; i >= start; i--) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
}

function bigIntToLe(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = 0; i < length; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Poly1305 one-time authenticator (RFC 8439 §2.5). */
export function poly1305(message: Uint8Array, key: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new Error('Poly1305 key must be 32 bytes');

  const r = leToBigInt(key, 0, 16) & R_CLAMP;
  const s = leToBigInt(key, 16, 32);

  let acc = 0n;
  for (let offset = 0; offset < message.length; offset += 16) {
    const end = Math.min(offset + 16, message.length);
    const block = message.subarray(offset, end);
    const n = leToBigInt(block) + (1n << BigInt(8 * block.length));
    acc = ((acc + n) * r) % P1305;
  }
  acc = (acc + s) & MASK128;
  return bigIntToLe(acc, 16);
}

function pad16(length: number): Uint8Array {
  const rem = length % 16;
  return new Uint8Array(rem === 0 ? 0 : 16 - rem);
}

function u64le(value: number): Uint8Array {
  const out = new Uint8Array(8);
  let v = BigInt(value);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export interface AeadResult {
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

function macData(aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const parts = [
    aad,
    pad16(aad.length),
    ciphertext,
    pad16(ciphertext.length),
    u64le(aad.length),
    u64le(ciphertext.length),
  ];
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Encrypt-then-MAC ChaCha20-Poly1305. */
export function aeadSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): AeadResult {
  if (nonce.length !== 12) throw new Error('AEAD nonce must be 12 bytes');
  const polyKey = chacha20Block(key, nonce, 0).slice(0, 32);
  const ciphertext = chacha20Xor(key, nonce, 1, plaintext);
  const tag = poly1305(macData(aad, ciphertext), polyKey);
  return { ciphertext, tag };
}

/** Verify and decrypt. Throws if the tag does not match. */
export function aeadOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): Uint8Array {
  if (nonce.length !== 12) throw new Error('AEAD nonce must be 12 bytes');
  const polyKey = chacha20Block(key, nonce, 0).slice(0, 32);
  const expected = poly1305(macData(aad, ciphertext), polyKey);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= expected[i] ^ (tag[i] ?? 0);
  if (diff !== 0) throw new Error('AEAD authentication failed');
  return chacha20Xor(key, nonce, 1, ciphertext);
}

/** Convenience: authenticated payload with ciphertext || tag. */
export function aeadSealCombined(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): Uint8Array {
  const { ciphertext, tag } = aeadSeal(key, nonce, plaintext, aad);
  const out = new Uint8Array(ciphertext.length + tag.length);
  out.set(ciphertext, 0);
  out.set(tag, ciphertext.length);
  return out;
}

export function aeadOpenCombined(
  key: Uint8Array,
  nonce: Uint8Array,
  combined: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): Uint8Array {
  if (combined.length < 16) throw new Error('AEAD payload too short');
  const ciphertext = combined.subarray(0, combined.length - 16);
  const tag = combined.subarray(combined.length - 16);
  return aeadOpen(key, nonce, ciphertext, tag, aad);
}
