/**
 * LDPC forward error correction utility.
 *
 * Retained as a standalone baseline after spatial rendering was removed; the
 * photonic carrier does not use it. Systematic `[A | I]` with `k = 2048` data
 * bits and `m = 1024` parity bits (`n = 3072`). A is sparse: each check row
 * touches `rowWeight` data bits, each data bit participates in
 * `columnWeight = m * rowWeight / k` checks. Every check also contains exactly
 * one parity bit (the identity block).
 *
 * Encoding only needs XORs: parity `p = A u`, so every check satisfies
 * `A u + I p = 0`. Decoding uses offset min-sum belief propagation.
 *
 * This is a deliberately small, dependency-free baseline. The construction is
 * deterministic for a given seed, but it is not an optimized 5G/Wi-Fi LDPC
 * code and has not been standardized.
 */

import { bytesToBits, bitsToBytes, xorshift32 } from '../util/bits.js';

export const LDPC_K = 2048;
export const LDPC_M = 1024;
export const LDPC_N = LDPC_K + LDPC_M;
export const LDPC_ROW_WEIGHT = 6;

export interface LdpcOptions {
  k?: number;
  m?: number;
  rowWeight?: number;
  seed?: number;
}

export interface LdpcDecodeResult {
  bits: Uint8Array;
  dataBits: Uint8Array;
  iterations: number;
  syndromeOk: boolean;
  /** Fraction of checks satisfied after the final iteration. */
  satisfiedRatio: number;
}

interface CheckNode {
  vars: Int32Array;
  /** Index of each variable's edge in `variableMessages[v]`. */
  edgeIndex: Int32Array;
}

interface VariableNode {
  checks: Int32Array;
  /** Index of this variable inside each check's edge list. */
  slots: Int32Array;
}

export class LdpcCode {
  readonly k: number;
  readonly m: number;
  readonly n: number;
  readonly rowWeight: number;
  private readonly checks: CheckNode[];
  private readonly variables: VariableNode[];

  constructor(options: LdpcOptions = {}) {
    this.k = options.k ?? LDPC_K;
    this.m = options.m ?? LDPC_M;
    this.n = this.k + this.m;
    this.rowWeight = options.rowWeight ?? LDPC_ROW_WEIGHT;
    if (this.rowWeight < 3) throw new Error('rowWeight must be >= 3');
    if (this.m * this.rowWeight < this.k) {
      throw new Error('rowWeight too small to cover every data bit');
    }

    const random = xorshift32(options.seed ?? 0x51c1a55);

    // Edge pool: each data bit appears `columnWeight` times. The pool is
    // shuffled and sliced into check rows. Duplicate columns inside a row are
    // repaired by swapping with later pool entries.
    const columnWeight = Math.max(2, Math.round((this.m * this.rowWeight) / this.k));
    const pool: number[] = [];
    for (let col = 0; col < this.k; col++) {
      for (let d = 0; d < columnWeight; d++) pool.push(col);
    }
    for (let i = pool.length - 1; i > 0; i--) {
      const j = Math.floor((random() / 0x100000000) * (i + 1));
      [pool[i], pool[j]] = [pool[j], pool[i]];
    }
    while (pool.length < this.m * this.rowWeight) pool.push(Math.floor(random() % this.k));

    const checks: CheckNode[] = [];
    for (let row = 0; row < this.m; row++) {
      const start = row * this.rowWeight;
      const vars: number[] = [];
      const seen = new Set<number>();
      for (let j = 0; j < this.rowWeight; j++) {
        let candidate = pool[start + j];
        if (seen.has(candidate)) {
          let swapped = -1;
          for (let t = start + this.rowWeight; t < pool.length; t++) {
            if (!seen.has(pool[t])) {
              swapped = t;
              break;
            }
          }
          if (swapped >= 0) {
            const replacement = pool[swapped];
            pool[swapped] = candidate;
            candidate = replacement;
          } else {
            for (let c = 0; c < this.k; c++) {
              if (!seen.has(c)) {
                candidate = c;
                break;
              }
            }
          }
        }
        seen.add(candidate);
        vars.push(candidate);
      }
      // Identity block: check row `row` owns parity variable `k + row`.
      vars.push(this.k + row);
      checks.push({ vars: Int32Array.from(vars), edgeIndex: new Int32Array(vars.length) });
    }

    const varChecks: number[][] = Array.from({ length: this.n }, () => []);
    const varSlots: number[][] = Array.from({ length: this.n }, () => []);
    checks.forEach((check, row) => {
      for (let slot = 0; slot < check.vars.length; slot++) {
        const variable = check.vars[slot];
        check.edgeIndex[slot] = varChecks[variable].length;
        varChecks[variable].push(row);
        varSlots[variable].push(slot);
      }
    });
    const variables: VariableNode[] = [];
    for (let v = 0; v < this.n; v++) {
      if (varChecks[v].length === 0) {
        throw new Error('LDPC construction left an uncovered variable bit');
      }
      variables.push({
        checks: Int32Array.from(varChecks[v]),
        slots: Int32Array.from(varSlots[v]),
      });
    }

    this.checks = checks;
    this.variables = variables;
  }

  /** Encode `k` data bits into `n` systematic codeword bits. */
  encode(dataBits: Uint8Array): Uint8Array {
    if (dataBits.length !== this.k) {
      throw new Error(`expected ${this.k} data bits, got ${dataBits.length}`);
    }
    const codeword = new Uint8Array(this.n);
    codeword.set(dataBits, 0);
    for (let row = 0; row < this.m; row++) {
      let parity = 0;
      const vars = this.checks[row].vars;
      for (let i = 0; i < vars.length - 1; i++) parity ^= dataBits[vars[i]] & 1;
      codeword[this.k + row] = parity;
    }
    return codeword;
  }

  /** Encode whole bytes (`k / 8` bytes). */
  encodeBytes(data: Uint8Array): Uint8Array {
    const expected = this.k / 8;
    if (data.length !== expected) {
      throw new Error(`expected ${expected} data bytes, got ${data.length}`);
    }
    return bitsToBytes(this.encode(bytesToBits(data)));
  }

  /** Check the parity equations for a codeword. */
  syndrome(codeword: Uint8Array): Uint8Array {
    const syndrome = new Uint8Array(this.m);
    for (let row = 0; row < this.m; row++) {
      let parity = 0;
      const vars = this.checks[row].vars;
      for (let i = 0; i < vars.length; i++) parity ^= codeword[vars[i]] & 1;
      syndrome[row] = parity;
    }
    return syndrome;
  }

  isCodeword(codeword: Uint8Array): boolean {
    const syndrome = this.syndrome(codeword);
    for (let i = 0; i < syndrome.length; i++) if (syndrome[i]) return false;
    return true;
  }

  /**
   * Offset min-sum decoding. `channelLlrs[i] = log(P(bit_i = 0) / P(bit_i = 1))`.
   */
  decode(
    channelLlrs: Float32Array,
    maxIterations = 40,
    offset = 0.3
  ): LdpcDecodeResult {
    if (channelLlrs.length !== this.n) {
      throw new Error(`expected ${this.n} LLRs, got ${channelLlrs.length}`);
    }

    const checkMessages: Float32Array[] = this.checks.map(
      (check) => new Float32Array(check.vars.length)
    );
    const variableMessages: Float32Array[] = this.variables.map(
      (variable) => new Float32Array(variable.checks.length)
    );
    const totals = new Float32Array(this.n);
    const hard = new Uint8Array(this.n);

    for (let iteration = 0; iteration < maxIterations; iteration++) {
      // Variable update: total observation = channel + incoming check messages.
      for (let v = 0; v < this.n; v++) {
        const variable = this.variables[v];
        let sum = channelLlrs[v];
        for (let i = 0; i < variable.checks.length; i++) {
          sum += checkMessages[variable.checks[i]][variable.slots[i]];
        }
        totals[v] = sum;
        for (let i = 0; i < variable.checks.length; i++) {
          variableMessages[v][i] = sum - checkMessages[variable.checks[i]][variable.slots[i]];
        }
      }

      // Hard decision and early exit.
      for (let i = 0; i < this.n; i++) hard[i] = totals[i] >= 0 ? 0 : 1;
      const syndrome = this.syndrome(hard);
      let satisfied = 0;
      for (let i = 0; i < syndrome.length; i++) if (!syndrome[i]) satisfied++;
      if (satisfied === this.m) {
        return {
          bits: hard,
          dataBits: hard.subarray(0, this.k),
          iterations: iteration + 1,
          syndromeOk: true,
          satisfiedRatio: 1,
        };
      }
      if (iteration === maxIterations - 1) break;

      // Check update: offset min-sum over the other incident variables.
      for (let row = 0; row < this.m; row++) {
        const check = this.checks[row];
        const messages = checkMessages[row];
        let signProduct = 1;
        let min1 = Infinity;
        let min2 = Infinity;
        let minIndex = -1;
        for (let i = 0; i < check.vars.length; i++) {
          const value = variableMessages[check.vars[i]][check.edgeIndex[i]];
          if (value < 0) signProduct = -signProduct;
          const magnitude = Math.abs(value);
          if (magnitude < min1) {
            min2 = min1;
            min1 = magnitude;
            minIndex = i;
          } else if (magnitude < min2) {
            min2 = magnitude;
          }
        }
        if (min2 === Infinity) min2 = min1;
        for (let i = 0; i < check.vars.length; i++) {
          const own = variableMessages[check.vars[i]][check.edgeIndex[i]];
          const sign = own < 0 ? -signProduct : signProduct;
          const magnitude = i === minIndex ? min2 : min1;
          messages[i] = sign * Math.max(0, magnitude - offset);
        }
      }
    }

    const syndrome = this.syndrome(hard);
    let satisfied = 0;
    for (let i = 0; i < syndrome.length; i++) if (!syndrome[i]) satisfied++;
    return {
      bits: hard,
      dataBits: hard.subarray(0, this.k),
      iterations: maxIterations,
      syndromeOk: satisfied === this.m,
      satisfiedRatio: satisfied / this.m,
    };
  }
}

/**
 * Build LLRs from hard decisions. `errorProbability` should reflect the
 * measured optical confidence (e.g. 0.01–0.1).
 */
export function llrFromBits(bits: Uint8Array, errorProbability = 0.05): Float32Array {
  const p = Math.min(0.49, Math.max(1e-6, errorProbability));
  const magnitude = Math.log((1 - p) / p);
  const llrs = new Float32Array(bits.length);
  for (let i = 0; i < bits.length; i++) {
    llrs[i] = bits[i] ? -magnitude : magnitude;
  }
  return llrs;
}

/** Build LLRs from per-bit error probabilities in (0, 0.5). */
export function llrFromReliabilities(
  bits: Uint8Array,
  errorProbabilities: ArrayLike<number>
): Float32Array {
  const llrs = new Float32Array(bits.length);
  for (let i = 0; i < bits.length; i++) {
    const p = Math.min(0.49, Math.max(1e-6, errorProbabilities[i] ?? 0.05));
    const magnitude = Math.log((1 - p) / p);
    llrs[i] = bits[i] ? -magnitude : magnitude;
  }
  return llrs;
}

export const defaultLdpcCode = new LdpcCode();
