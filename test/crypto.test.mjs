import test from 'node:test';
import assert from 'node:assert/strict';

import {
  sha3_256,
  sha3_512,
  shake128,
  shake256,
  toHex,
} from '../dist/crypto/keccak.js';
import {
  aeadSeal,
  aeadOpen,
  aeadSealCombined,
  aeadOpenCombined,
} from '../dist/crypto/chacha20poly1305.js';
import {
  mulPoly,
  schoolbookMul,
  encodePoly12,
  decodePoly12,
  messageToPoly,
  polyToMessage,
} from '../dist/crypto/poly.js';
import {
  mlkemKeygen,
  mlkemEncapsulate,
  mlkemDecapsulate,
  MLKEM_PUBLIC_KEY_BYTES,
  MLKEM_SECRET_KEY_BYTES,
  MLKEM_CIPHERTEXT_BYTES,
} from '../dist/crypto/mlkem.js';

const utf8 = (s) => new TextEncoder().encode(s);
const fromHex = (h) => Uint8Array.from(h.match(/.{2}/g).map((b) => parseInt(b, 16)));

test('SHA3-256 known vectors', () => {
  assert.equal(
    toHex(sha3_256(new Uint8Array(0))),
    'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'
  );
  assert.equal(
    toHex(sha3_256(utf8('abc'))),
    '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'
  );
});

test('SHA3-512 known vector', () => {
  assert.equal(
    toHex(sha3_512(utf8('abc'))),
    'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e' +
      '10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0'
  );
});

test('SHAKE128 / SHAKE256 known vectors', () => {
  assert.equal(
    toHex(shake128(new Uint8Array(0), 32)),
    '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'
  );
  assert.equal(
    toHex(shake256(new Uint8Array(0), 32)),
    '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f'
  );
});

test('ChaCha20-Poly1305 RFC 8439 §2.8.2 vector', () => {
  const key = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
  const nonce = fromHex('070000004041424344454647');
  const aad = fromHex('50515253c0c1c2c3c4c5c6c7');
  const plaintext = utf8(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
  );
  const expectedCiphertext =
    'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6' +
    '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36' +
    '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc' +
    '3ff4def08e4b7a9de576d26586cec64b6116';
  const expectedTag = '1ae10b594f09e26a7e902ecbd0600691';

  const { ciphertext, tag } = aeadSeal(key, nonce, plaintext, aad);
  assert.equal(toHex(ciphertext), expectedCiphertext);
  assert.equal(toHex(tag), expectedTag);

  const opened = aeadOpen(key, nonce, ciphertext, tag, aad);
  assert.deepEqual(Array.from(opened), Array.from(plaintext));

  // Tampering must fail.
  const bad = new Uint8Array(ciphertext);
  bad[0] ^= 1;
  assert.throws(() => aeadOpen(key, nonce, bad, tag, aad), /authentication/);

  // Combined helper roundtrip.
  const combined = aeadSealCombined(key, nonce, plaintext, aad);
  assert.deepEqual(Array.from(aeadOpenCombined(key, nonce, combined, aad)), Array.from(plaintext));
});

test('NTT multiplication matches schoolbook negacyclic multiplication', () => {
  let seed = 123456789;
  const rand = () => {
    seed = (seed * 1103515245 + 12345) >>> 0;
    return seed / 0x100000000;
  };
  const a = new Int32Array(256);
  const b = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    a[i] = Math.floor(rand() * 3329);
    b[i] = Math.floor(rand() * 3329);
  }
  assert.deepEqual(Array.from(mulPoly(a, b)), Array.from(schoolbookMul(a, b)));
});

test('12-bit poly and message poly roundtrip', () => {
  const poly = new Int32Array(256);
  for (let i = 0; i < 256; i++) poly[i] = (i * 13) % 3329;
  assert.deepEqual(Array.from(decodePoly12(encodePoly12(poly))), Array.from(poly));

  const message = Uint8Array.from({ length: 32 }, (_, i) => (i * 37) & 0xff);
  assert.deepEqual(Array.from(polyToMessage(messageToPoly(message))), Array.from(message));
});

test('ML-KEM keygen/encaps/decaps roundtrip and implicit rejection', () => {
  const seed = new Uint8Array(32).fill(7);
  const { publicKey, secretKey } = mlkemKeygen(seed);
  assert.equal(publicKey.length, MLKEM_PUBLIC_KEY_BYTES);
  assert.equal(secretKey.length, MLKEM_SECRET_KEY_BYTES);

  const { ciphertext, sharedSecret } = mlkemEncapsulate(
    publicKey,
    new Uint8Array(32).fill(9)
  );
  assert.equal(ciphertext.length, MLKEM_CIPHERTEXT_BYTES);
  assert.equal(sharedSecret.length, 32);

  const recovered = mlkemDecapsulate(secretKey, ciphertext);
  assert.deepEqual(Array.from(recovered), Array.from(sharedSecret));

  // Corrupted ciphertext must not throw, and must not return the real secret.
  const tampered = new Uint8Array(ciphertext);
  tampered[100] ^= 0x40;
  const rejected = mlkemDecapsulate(secretKey, tampered);
  assert.equal(rejected.length, 32);
  assert.notDeepEqual(Array.from(rejected), Array.from(sharedSecret));
});

test('ML-KEM is deterministic for fixed seeds', () => {
  const seed = new Uint8Array(32).fill(3);
  const a = mlkemKeygen(seed);
  const b = mlkemKeygen(seed);
  assert.deepEqual(Array.from(a.publicKey), Array.from(b.publicKey));
  assert.deepEqual(Array.from(a.secretKey.slice(0, 1152)), Array.from(b.secretKey.slice(0, 1152)));

  const r1 = mlkemEncapsulate(a.publicKey, new Uint8Array(32).fill(5));
  const r2 = mlkemEncapsulate(b.publicKey, new Uint8Array(32).fill(5));
  assert.deepEqual(Array.from(r1.ciphertext), Array.from(r2.ciphertext));
  assert.deepEqual(Array.from(r1.sharedSecret), Array.from(r2.sharedSecret));
});
