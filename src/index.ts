/**
 * clasp-photonic-pairing
 *
 * Post-quantum photonic pairing via dual-camera capture.
 *
 * Analyzes two sequential QR code photos captured from a mobile device camera
 * and derives a unique 256-bit cryptographic handshake key using the
 * Dual-Coordinate Overlap Framework.
 *
 * No external cryptographic dependencies. Uses only the browser's built-in
 * Camera/ImageCapture API (for capture) and Canvas (for pixel access), plus
 * a built-in SHA-256 for digest condensation.
 *
 * WARNING: This is experimental custom cryptography. It has not undergone
 * formal cryptanalysis. For high-security production, wrap it inside a proven
 * cipher such as AES-GCM. Do not use as the sole cipher. See README.md for
 * full caveats.
 */

export {
  PhotonicQuantumAnalyzer,
  imageBitmapToGrayscaleArray,
  sha256Hex,
  mapToHilbertState,
  applyUnitaryPhaseTranslation,
  computeRiemannFilter,
  overlapTunnelingFormula,
  float64ToBytes,
  RIEMANN_ZEROS,
  KOTTMAN_CONSTANT,
  R_INFINITY,
} from './photonicQuantumAnalyzer';

export {
  EntropyCryptoPool,
  entropyCryptoPool,
} from './entropyCryptoPool';

export {
  capturePhotonicPasskey,
  derivePasskeyFromDigest,
  verifyPhotonicPasskey,
} from './photonicPairing';
export type {
  Complex,
  PhotonicAnalysisResult,
} from './photonicQuantumAnalyzer';
export type {
  PhotonicPairingResult,
  PhotonicEnrollment,
} from './photonicPairing';
