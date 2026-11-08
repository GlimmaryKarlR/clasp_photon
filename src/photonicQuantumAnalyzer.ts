/**
 * PhotonicQuantumAnalyzer — Dual-Photo Photonic Quantum Analyzer
 *
 * Analyzes two sequential QR code photos captured from a mobile device camera
 * and derives a unique 256-bit cryptographic handshake key from subtle
 * photonic / photoelectric variations between the frames.
 *
 * Based on the Dual-Coordinate Overlap Framework:
 *   - System A: 4D Minkowski spacetime particle frame X_A = (x, y, z, t)
 *   - System B: Infinite-dimensional Hilbert space wave frame Θ_B = (θ₁, θ₂, …)
 *   - Coupling via imaginary parts of non-trivial Riemann zeros γₙ
 *
 * No external cryptographic dependencies. Uses only the browser's built-in
 * Camera/ImageCapture API (for capture) and Canvas (for pixel access), plus
 * a built-in SHA-256 for digest condensation.
 *
 * WARNING: This is experimental custom cryptography. It has not undergone
 * formal cryptanalysis. Do not use as the sole cipher for high-security
 * production systems without wrapping it inside a proven cipher such as
 * AES-GCM. See README.md for full caveats.
 */

export const RIEMANN_ZEROS: readonly number[] = [
  14.1347251417346937, 21.0220396387715550, 25.0108575801456887, 30.4248761258595132,
  32.9350615877391897, 37.5861781588256713, 40.9187190121474952, 43.3270732809149995,
  48.0051508811671597, 49.7738324776723022, 52.9703214777144606, 56.1122850192308058,
  59.3470440026023531, 60.8317785246098098, 65.1125440480816067, 67.0798105294941737,
];

export const KOTTMAN_CONSTANT = Math.SQRT2;
export const R_INFINITY = 1.0 / (1.0 + Math.SQRT2); // ~0.41421356

export interface Complex {
  real: number;
  imag: number;
}

export interface PhotonicAnalysisResult {
  /** 256-bit hex digest derived from the two captured frames */
  photonicDigest: string;
  /** Chordal distance between the two Hilbert state vectors */
  hilbertChordalDistance: number;
  /** Kottman packing radius limit (~0.4142) */
  kottmanPackingLimit: number;
  /** Ratio of resonant tunneling events to total samples (0–1) */
  filteredTunnelingRatio: number;
  /** Whether the pair passes the quantum authenticity gate */
  isQuantumAuthentic: boolean;
  /** Number of pixel samples analyzed */
  totalSamples: number;
}

/**
 * Maps a 4D spacetime/intensity vector X = (x, y, delta_I, dt) into active
 * complex Hilbert space components.
 * cₙ(X) = (1 / √2ⁿ⁺¹) * exp(i * π * Xⁿ / γₙ)
 */
export function mapToHilbertState(
  X: number[],
  gamma: readonly number[],
  activeDims: number
): Complex[] {
  const c: Complex[] = [];
  for (let n = 0; n < activeDims; n++) {
    const normFactor = 1.0 / Math.sqrt(2 ** (n + 1));
    c.push({
      real: normFactor * Math.cos(Math.PI * X[n] / gamma[n]),
      imag: normFactor * Math.sin(Math.PI * X[n] / gamma[n]),
    });
  }
  return c;
}

/**
 * Applies Unitary Translation Operator:
 * U_hat(ΔX) |eₙ⟩ = exp(i * π * ΔXⁿ / γₙ) |eₙ⟩
 */
export function applyUnitaryPhaseTranslation(
  state: Complex[],
  deltaX: number[],
  gamma: readonly number[],
  activeDims: number
): Complex[] {
  const translated: Complex[] = [];
  for (let n = 0; n < activeDims; n++) {
    const uReal = Math.cos(Math.PI * deltaX[n] / gamma[n]);
    const uImag = Math.sin(Math.PI * deltaX[n] / gamma[n]);
    translated.push({
      real: state[n].real * uReal - state[n].imag * uImag,
      imag: state[n].real * uImag + state[n].imag * uReal,
    });
  }
  return translated;
}

/**
 * Evaluates the Riemann Filter operator:
 * F(a) = ∏ₙ₌₁ᴺ cos²(π * a / γₙ)
 */
export function computeRiemannFilter(
  aWidth: number,
  gamma: readonly number[],
  activeDims: number
): number {
  let product = 1.0;
  for (let n = 0; n < activeDims; n++) {
    product *= Math.cos(Math.PI * aWidth / gamma[n]) ** 2;
  }
  return product;
}

/**
 * Computes transmission probability:
 * T(E) = [1 + (V₀² / (4E(V₀−E))) * sinh²(κa * F(a))]⁻¹
 *
 * Filters out classical macro-fluctuations while permitting resonant
 * micro-photonic fluctuations (T(E) → 1).
 */
export function overlapTunnelingFormula(
  E: number,
  V0: number,
  aWidth: number,
  gamma: readonly number[],
  activeDims: number,
  m = 1.0,
  hbar = 1.0
): number {
  if (E >= V0 || E <= 0) {
    return E >= V0 ? 1.0 : 0.0;
  }

  const kappa = Math.sqrt(2.0 * m * (V0 - E)) / hbar;
  const F_a = computeRiemannFilter(aWidth, gamma, activeDims);

  const mismatch = (V0 ** 2) / (4.0 * E * (V0 - E));
  const sinhArg = Math.max(-50, Math.min(50, kappa * aWidth * F_a));
  const denom = 1.0 + mismatch * Math.sinh(sinhArg) ** 2;
  return 1.0 / denom;
}

/**
 * Converts a float64 value to 8 bytes (big-endian).
 */
export function float64ToBytes(value: number): number[] {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setFloat64(0, value, false);
  return Array.from(new Uint8Array(buf));
}

/**
 * SHA-256 hex digest of a Uint8Array.
 */
export function sha256Hex(data: Uint8Array): string {
  const hash = sha256Bytes(data);
  return Array.from(hash)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Pure TypeScript SHA-256 implementation (FIPS 180-4).
 * No external dependencies.
 */
function sha256Bytes(data: Uint8Array): Uint8Array {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  let H0 = 0x6a09e667;
  let H1 = 0xbb67ae85;
  let H2 = 0x3c6ef372;
  let H3 = 0xa54ff53a;
  let H4 = 0x510e527f;
  let H5 = 0x9b05688c;
  let H6 = 0x1f83d9ab;
  let H7 = 0x5be0cd19;

  const dataLen = data.length;
  const bitLen = dataLen * 8;
  const withOne = dataLen + 1;
  const paddedLen = Math.ceil((withOne + 8) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(data);
  padded[dataLen] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 4, bitLen >>> 0, false);
  view.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false);

  const W = new Uint32Array(64);

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 =
        rightRotate(W[i - 15], 7) ^
        rightRotate(W[i - 15], 18) ^
        (W[i - 15] >>> 3);
      const s1 =
        rightRotate(W[i - 2], 17) ^
        rightRotate(W[i - 2], 19) ^
        (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }

    let a = H0;
    let b = H1;
    let c = H2;
    let d = H3;
    let e = H4;
    let f = H5;
    let g = H6;
    let h = H7;

    for (let i = 0; i < 64; i++) {
      const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
      const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    H0 = (H0 + a) >>> 0;
    H1 = (H1 + b) >>> 0;
    H2 = (H2 + c) >>> 0;
    H3 = (H3 + d) >>> 0;
    H4 = (H4 + e) >>> 0;
    H5 = (H5 + f) >>> 0;
    H6 = (H6 + g) >>> 0;
    H7 = (H7 + h) >>> 0;
  }

  const result = new Uint8Array(32);
  const outView = new DataView(result.buffer);
  outView.setUint32(0, H0, false);
  outView.setUint32(4, H1, false);
  outView.setUint32(8, H2, false);
  outView.setUint32(12, H3, false);
  outView.setUint32(16, H4, false);
  outView.setUint32(20, H5, false);
  outView.setUint32(24, H6, false);
  outView.setUint32(28, H7, false);
  return result;
}

/**
 * Right rotate a 32-bit value.
 */
function rightRotate(value: number, amount: number): number {
  return (value >>> amount) | (value << (32 - amount));
}

/**
 * Converts an ImageBitmap to a grayscale 2D number array (0–255).
 */
export async function imageBitmapToGrayscaleArray(
  bitmap: ImageBitmap
): Promise<number[][]> {
  const width = bitmap.width;
  const height = bitmap.height;

  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    throw new Error('Failed to create canvas context');
  }

  ctx.drawImage(bitmap, 0, 0);
  const imageData = ctx.getImageData(0, 0, width, height);
  const data = imageData.data;

  const gray: number[][] = [];
  for (let y = 0; y < height; y++) {
    gray[y] = [];
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 4;
      const r = data[i];
      const g = data[i + 1];
      const b = data[i + 2];
      gray[y][x] = 0.299 * r + 0.587 * g + 0.114 * b;
    }
  }

  return gray;
}

/**
 * PhotonicQuantumAnalyzer — main class.
 *
 * Captures two sequential QR code photos and analyzes subtle photonic
 * / photoelectric variations using the Dual-Coordinate Overlap Framework.
 */
export class PhotonicQuantumAnalyzer {
  readonly activeDims: number;
  readonly gamma: readonly number[];

  constructor(activeDims = 4, numZeros = 16) {
    this.activeDims = activeDims;
    this.gamma = RIEMANN_ZEROS.slice(0, numZeros);
  }

  /**
   * Compares two 2D image arrays (grayscale QR code frames) and extracts
   * high-dimensional quantum photoelectric signatures.
   *
   * Returns a PhotonicAnalysisResult with the condensed 256-bit digest.
   */
  analyzePhotoPair(
    img1: number[][],
    img2: number[][],
    deltaTMs = 33.3
  ): PhotonicAnalysisResult {
    const height = img1.length;
    const width = img1[0].length;

    if (img2.length !== height || img2[0].length !== width) {
      throw new Error('Input images must have matching dimensions.');
    }

    // 1. Compute pixel-level spatial intensity difference field (Delta I)
    const diffField: number[][] = [];
    for (let y = 0; y < height; y++) {
      diffField[y] = [];
      for (let x = 0; x < width; x++) {
        diffField[y][x] = img2[y][x] - img1[y][x];
      }
    }

    // Global Hilbert accumulator vectors for both frames
    const stateAcc1: Complex[] = Array.from({ length: this.activeDims }, () => ({
      real: 0,
      imag: 0,
    }));
    const stateAcc2: Complex[] = Array.from({ length: this.activeDims }, () => ({
      real: 0,
      imag: 0,
    }));

    // Sample key spatial regions (QR alignment patterns / grid nodes)
    const sampleStep = Math.max(1, Math.floor(Math.min(height, width) / 32));

    let totalSamples = 0;
    let filteredTunnelingEnergy = 0.0;

    for (let y = 0; y < height; y += sampleStep) {
      for (let x = 0; x < width; x += sampleStep) {
        const val1 = img1[y][x] / 255.0;
        const val2 = img2[y][x] / 255.0;
        const deltaI = diffField[y][x] / 255.0;

        // 4D Spacetime coordinate vectors X = (x_norm, y_norm, intensity, time)
        const X1 = [x / width, y / height, val1, 0.0];
        const X2 = [x / width, y / height, val2, deltaTMs / 1000.0];
        const deltaX = [
          X2[0] - X1[0],
          X2[1] - X1[1],
          X2[2] - X1[2],
          X2[3] - X1[3],
        ];

        // Map image pixels to Hilbert space
        const h1 = mapToHilbertState(X1, this.gamma, this.activeDims);
        const h2 = mapToHilbertState(X2, this.gamma, this.activeDims);

        // Apply Unitary Translation Operator across System B
        const h1Translated = applyUnitaryPhaseTranslation(
          h1,
          deltaX,
          this.gamma,
          this.activeDims
        );

        // Apply Overlap Tunneling Filter based on micro-step width
        const aWidth =
          Math.sqrt(
            deltaX.reduce((sum, v) => sum + v * v, 0)
          ) + 1e-5;
        const E_eff = Math.max(0.01, Math.abs(deltaI));
        const V0_eff = E_eff + 0.5;
        const T_eff = overlapTunnelingFormula(
          E_eff,
          V0_eff,
          aWidth,
          this.gamma,
          this.activeDims
        );

        for (let n = 0; n < this.activeDims; n++) {
          stateAcc1[n].real += h1Translated[n].real * T_eff;
          stateAcc1[n].imag += h1Translated[n].imag * T_eff;
          stateAcc2[n].real += h2[n].real * T_eff;
          stateAcc2[n].imag += h2[n].imag * T_eff;
        }

        filteredTunnelingEnergy += T_eff;
        totalSamples++;
      }
    }

    // Normalize Hilbert accumulator states
    const norm1 = Math.sqrt(
      stateAcc1.reduce(
        (s, c) => s + c.real * c.real + c.imag * c.imag,
        0
      )
    );
    const norm2 = Math.sqrt(
      stateAcc2.reduce(
        (s, c) => s + c.real * c.real + c.imag * c.imag,
        0
      )
    );

    if (norm1 > 0) {
      for (let n = 0; n < this.activeDims; n++) {
        stateAcc1[n].real /= norm1;
        stateAcc1[n].imag /= norm1;
      }
    }
    if (norm2 > 0) {
      for (let n = 0; n < this.activeDims; n++) {
        stateAcc2[n].real /= norm2;
        stateAcc2[n].imag /= norm2;
      }
    }

    // 2. Evaluate Hilbert Space Chordal Distance between frames
    let distSq = 0;
    for (let n = 0; n < this.activeDims; n++) {
      const dr = stateAcc1[n].real - stateAcc2[n].real;
      const di = stateAcc1[n].imag - stateAcc2[n].imag;
      distSq += dr * dr + di * di;
    }
    const hilbertDistance = Math.sqrt(distSq);

    // 3. Check against Kottman Constant Limit and packing radius
    const isQuantumAuthentic =
      hilbertDistance <= R_INFINITY && filteredTunnelingEnergy > 0;

    // 4. Generate condensed 256-bit Photonic Digest
    const digestBytes: number[] = [];
    for (const c of stateAcc1) {
      digestBytes.push(...float64ToBytes(c.real));
      digestBytes.push(...float64ToBytes(c.imag));
    }
    for (const c of stateAcc2) {
      digestBytes.push(...float64ToBytes(c.real));
      digestBytes.push(...float64ToBytes(c.imag));
    }
    digestBytes.push(...float64ToBytes(hilbertDistance));

    const photonicDigest = sha256Hex(new Uint8Array(digestBytes));

    return {
      photonicDigest,
      hilbertChordalDistance: hilbertDistance,
      kottmanPackingLimit: R_INFINITY,
      filteredTunnelingRatio: filteredTunnelingEnergy / Math.max(1, totalSamples),
      isQuantumAuthentic,
      totalSamples,
    };
  }
}
