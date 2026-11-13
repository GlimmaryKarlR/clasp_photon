#!/usr/bin/env node
/**
 * Cross-check the Rust native core against the TypeScript reference.
 *
 * Proves byte-for-byte agreement for deterministic keygen, encapsulation and
 * decapsulation (including the implicit-rejection path). Any NTT, sampling,
 * encoding or hash divergence shows up immediately.
 *
 * Usage: node scripts/crosscheck-native.mjs
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  mlkemKeygen,
  mlkemEncapsulate,
  mlkemDecapsulate,
} from '../dist/crypto/mlkem.js';
import { sha3_256 } from '../dist/crypto/keccak.js';
import { ntt as tsNttFunction } from '../dist/crypto/poly.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(root, 'native', 'target', 'release', 'photon_cli');

if (!existsSync(cli)) {
  console.error('missing native CLI — run ./scripts/build-native.sh first');
  process.exit(1);
}

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (value) => Uint8Array.from(Buffer.from(value, 'hex'));

function run(args) {
  const output = execFileSync(cli, args, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  const result = {};
  for (const line of output.trim().split('\n')) {
    const [key, value] = line.split('=');
    result[key] = value;
  }
  return result;
}

function expectEqual(label, a, b) {
  if (a !== b) {
    console.error(`FAIL ${label}: length TS=${a.length} Rust=${b.length}`);
    for (let i = 0; i < Math.min(a.length, b.length); i += 2) {
      if (a.slice(i, i + 2) !== b.slice(i, i + 2)) {
        console.error(`  first difference at byte ${i / 2}`);
        console.error(`  TS  : ...${a.slice(Math.max(0, i - 8), i + 16)}...`);
        console.error(`  Rust: ...${b.slice(Math.max(0, i - 8), i + 16)}...`);
        break;
      }
    }
    process.exitCode = 1;
    return;
  }
  console.log(`[OK] ${label} (${a.length / 2} bytes)`);
}

console.log('=== Rust ↔ TypeScript ML-KEM cross-check ===\n');

const seed = new Uint8Array(32).fill(7);
const randomness = new Uint8Array(32).fill(9);

// 1. Deterministic keygen
const tsKeys = mlkemKeygen(seed);
const rustKeys = run(['keygen', hex(seed)]);
expectEqual('public key', hex(tsKeys.publicKey), rustKeys.pk);
expectEqual('secret key', hex(tsKeys.secretKey), rustKeys.sk);

// 2. Encapsulation
const tsEnc = mlkemEncapsulate(tsKeys.publicKey, randomness);
const rustEnc = run(['encaps', rustKeys.pk, hex(randomness)]);
expectEqual('ciphertext', hex(tsEnc.ciphertext), rustEnc.ct);
expectEqual('shared secret', hex(tsEnc.sharedSecret), rustEnc.ss);

// 3. Decapsulation (TS ciphertext -> Rust secret key)
const rustDec = run(['decaps', rustKeys.sk, hex(tsEnc.ciphertext)]);
expectEqual('decapsulated secret', hex(tsEnc.sharedSecret), rustDec.ss);

// 4. Cross direction: Rust ciphertext -> TS secret key
const tsDec = mlkemDecapsulate(tsKeys.secretKey, unhex(rustEnc.ct));
expectEqual('cross decapsulation', hex(tsEnc.sharedSecret), hex(tsDec));

// 5. Implicit rejection must also agree byte-for-byte.
const tampered = new Uint8Array(tsEnc.ciphertext);
tampered[100] ^= 0x40;
const tsRejected = mlkemDecapsulate(tsKeys.secretKey, tampered);
const rustRejected = run(['decaps', rustKeys.sk, hex(tampered)]);
expectEqual('implicit rejection', hex(tsRejected), rustRejected.ss);

// 6. WASM artifact must expose the same results through its statics ABI.
const wasmPath = join(root, 'dist', 'clasp_photon_wasm.wasm');
if (!existsSync(wasmPath)) {
  console.error('missing dist/clasp_photon_wasm.wasm — run ./scripts/build-native.sh first');
  process.exitCode = 1;
} else {
  const wasmBytes = readFileSync(wasmPath);
  const { instance } = await WebAssembly.instantiate(wasmBytes, {});
  const wasm = instance.exports;

  const write = (pointer, bytes) => {
    new Uint8Array(wasm.memory.buffer, pointer, bytes.length).set(bytes);
  };
  const read = (pointer, length) =>
    new Uint8Array(wasm.memory.buffer, pointer, length).slice();

  const z = sha3_256(new Uint8Array([...seed, 0x5a]));
  write(wasm.photon_seed_ptr(), seed);
  write(wasm.photon_z_ptr(), z);
  if (wasm.photon_keygen() !== 0) throw new Error('wasm keygen failed');
  expectEqual('wasm public key', hex(tsKeys.publicKey), hex(read(wasm.photon_pk_ptr(), 1184)));
  expectEqual('wasm secret key', hex(tsKeys.secretKey), hex(read(wasm.photon_sk_ptr(), 2400)));

  write(wasm.photon_randomness_ptr(), randomness);
  if (wasm.photon_encaps() !== 0) throw new Error('wasm encaps failed');
  expectEqual('wasm ciphertext', hex(tsEnc.ciphertext), hex(read(wasm.photon_ct_ptr(), 1088)));
  expectEqual('wasm shared secret', hex(tsEnc.sharedSecret), hex(read(wasm.photon_ss_ptr(), 32)));

  if (wasm.photon_decaps() !== 0) throw new Error('wasm decaps failed');
  expectEqual('wasm decapsulated secret', hex(tsEnc.sharedSecret), hex(read(wasm.photon_ss_ptr(), 32)));

  const message = new TextEncoder().encode('wasm sha3 check');
  write(wasm.photon_input_ptr(), message);
  wasm.photon_input_set_len(message.length);
  if (wasm.photon_sha3_256() !== 0) throw new Error('wasm sha3 failed');
  expectEqual(
    'wasm sha3-256',
    hex(sha3_256(message)),
    hex(read(wasm.photon_digest_ptr(), 32))
  );

  const poly = Array.from({ length: 256 }, (_, i) => (i * 17 + 5) % 3329);
  const nttInput = new Int32Array(wasm.memory.buffer, wasm.photon_ntt_buffer_ptr(), 256);
  nttInput.set(poly);
  wasm.photon_ntt();
  const wasmNtt = Array.from(nttInput);
  const tsNtt = tsNttFunction(poly);
  if (wasmNtt.some((value, i) => value !== tsNtt[i])) {
    console.error('FAIL wasm NTT: output differs from TypeScript reference');
    process.exitCode = 1;
  } else {
    console.log('[OK] wasm NTT (256 coefficients)');
  }
}

if (process.exitCode) {
  console.error('\n=== CROSS-CHECK FAILED ===');
} else {
  console.log('\n=== CROSS-CHECK PASS === Rust, WASM and TypeScript cores agree.');
}
