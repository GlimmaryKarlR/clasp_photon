/**
 * QuaNet quanta — the smallest addressable unit of data.
 *
 * A quanta carries two independent properties:
 *   spin  ∈ {0, ½, 1}   — three spin states, encoded as two bits
 *   qubit ∈ {0, 1}      — the resolved qubit state
 *
 * 3 × 2 = 6 states, base-6 packed into a byte stream. The large XNOR fabric
 * compares spins first, then qubits, then XNORs the two masks. The result
 * resolves overlapping quanta (collapse) and fingerprints message chains.
 *
 * This is the portable reference used by clasp_mobile, which adds the QDL
 * renderer on top.
 */

import { sha256Hex } from '../photonicQuantumAnalyzer.js';

export type Spin = 0 | 0.5 | 1;
export type Qubit = 0 | 1;
export type Bit = 0 | 1;

export interface Quanta {
  spin: Spin;
  qubit: Qubit;
}

const SPIN_ORDER: Spin[] = [0, 0.5, 1];
export const QUANTA_STATE_COUNT = 6;

function spinIndex(spin: Spin): 0 | 1 | 2 {
  return spin === 0 ? 0 : spin === 0.5 ? 1 : 2;
}

export function quantaState(q: Quanta): number {
  return spinIndex(q.spin) * 2 + q.qubit;
}

export function stateToQuanta(state: number): Quanta {
  const s = ((state % QUANTA_STATE_COUNT) + QUANTA_STATE_COUNT) % QUANTA_STATE_COUNT;
  return { spin: SPIN_ORDER[Math.floor(s / 2)], qubit: (s % 2) as Qubit };
}

export function encodeQuanta(bytes: Uint8Array): Quanta[] {
  if (bytes.length === 0) return [];
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  const digits: number[] = [];
  while (value > 0n) {
    digits.push(Number(value % 6n));
    value /= 6n;
  }
  digits.reverse();
  return digits.map(stateToQuanta);
}

export function decodeQuanta(quanta: Quanta[], byteLength: number): Uint8Array {
  const out = new Uint8Array(Math.max(0, byteLength));
  if (out.length === 0) return out;
  let value = 0n;
  for (const q of quanta) value = value * 6n + BigInt(quantaState(q));
  for (let i = out.length - 1; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

export function xnor(a: Bit, b: Bit): Bit {
  return a === b ? 1 : 0;
}

export interface XnorFabric {
  spinMask: Bit[];
  qubitMask: Bit[];
  resolved: Bit[];
  signature: string;
}

export function resolveXnorFabric(a: Quanta[], b: Quanta[]): XnorFabric {
  const count = Math.max(a.length, b.length);
  const spinMask: Bit[] = [];
  const qubitMask: Bit[] = [];
  const resolved: Bit[] = [];
  for (let i = 0; i < count; i++) {
    const left = a[i] ?? { spin: 0 as Spin, qubit: 0 as Qubit };
    const right = b[i] ?? { spin: 0 as Spin, qubit: 0 as Qubit };
    const spinEq: Bit = left.spin === right.spin ? 1 : 0;
    const qubitEq: Bit = left.qubit === right.qubit ? 1 : 0;
    spinMask.push(spinEq);
    qubitMask.push(qubitEq);
    resolved.push(xnor(spinEq, qubitEq));
  }
  const signature = sha256Hex(
    new TextEncoder().encode(`${a.length}:${b.length}:${resolved.join('')}`)
  );
  return { spinMask, qubitMask, resolved, signature };
}

export function collapse(a: Quanta[], b: Quanta[], fabric: XnorFabric): Quanta[] {
  const out: Quanta[] = [];
  for (let i = 0; i < fabric.resolved.length; i++) {
    const chosen = fabric.resolved[i] === 1 ? a[i] ?? b[i] : b[i] ?? a[i];
    if (chosen) out.push(chosen);
  }
  return out;
}

export function quantaFingerprint(quanta: Quanta[]): string {
  return sha256Hex(new TextEncoder().encode(quanta.map(quantaState).join('')));
}
