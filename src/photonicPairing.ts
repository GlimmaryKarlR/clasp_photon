/**
 * PhotonicPairing — High-level pairing + 2FA workflow
 *
 * Wraps PhotonicQuantumAnalyzer with the full enrollment and verification
 * lifecycle for desktop↔mobile pairing and two-factor replacement.
 *
 * No external crypto dependencies.
 */

import {
  PhotonicQuantumAnalyzer,
  imageBitmapToGrayscaleArray,
  sha256Hex,
} from './photonicQuantumAnalyzer.js';

export interface PhotonicPairingResult {
  photonicDigest: string;
  derivedPasskey: string;
  isQuantumAuthentic: boolean;
  hilbertChordalDistance: number;
  timestamp: number;
}

export interface PhotonicEnrollment {
  peerId: string;
  photonicDigest: string;
  derivedPasskey: string;
  enrolledAt: number;
}

/**
 * Captures two photos and derives a passkey locally (no desktop round-trip).
 * Use this on the mobile side to generate a passkey for a peer.
 */
export async function capturePhotonicPasskey(
  peerId: string,
  currentUser: string,
  deltaTMs = 33.3
): Promise<PhotonicPairingResult | null> {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    const track = stream.getVideoTracks()[0];
    const imageCapture = new (window as any).ImageCapture(track);

    const bitmap1 = await imageCapture.grabFrame();
    await new Promise((r) => setTimeout(r, deltaTMs));
    const bitmap2 = await imageCapture.grabFrame();
    track.stop();

    const arr1 = await imageBitmapToGrayscaleArray(bitmap1);
    const arr2 = await imageBitmapToGrayscaleArray(bitmap2);

    const analyzer = new PhotonicQuantumAnalyzer();
    const result = analyzer.analyzePhotoPair(arr1, arr2, deltaTMs);

    if (!result.isQuantumAuthentic) {
      return null;
    }

    const derivedPasskey = sha256Hex(
      new TextEncoder().encode(
        `${result.photonicDigest}:${peerId}:${currentUser}`
      )
    );

    return {
      photonicDigest: result.photonicDigest,
      derivedPasskey,
      isQuantumAuthentic: result.isQuantumAuthentic,
      hilbertChordalDistance: result.hilbertChordalDistance,
      timestamp: Date.now(),
    };
  } catch (err) {
    console.warn('Photonic capture failed:', err);
    return null;
  }
}

/**
 * Server-side helper: derive passkey from photonic digest.
 * Call this on the desktop after receiving the digest from mobile.
 */
export function derivePasskeyFromDigest(
  photonicDigest: string,
  peerId: string,
  desktopId: string
): string {
  return sha256Hex(
    new TextEncoder().encode(`${photonicDigest}:${peerId}:${desktopId}`)
  );
}

/**
 * Verifies a photonic passkey against a stored enrollment.
 */
export function verifyPhotonicPasskey(
  storedPasskey: string,
  candidatePasskey: string
): boolean {
  return storedPasskey === candidatePasskey;
}
