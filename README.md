# clasp_photon

**Post-quantum encryption**

No external cryptographic dependencies. 

---

## QuaNet

```
▄█████▄ ▄▄ ▄▄  ▄▄▄  ███  ██ ▄▄▄▄▄ ▄▄▄▄▄▄ 
██ ▄ ██ ██ ██ ██▀██ ██ ▀▄██ ██▄▄    ██   
▀█████▀ ▀███▀ ██▀██ ██   ██ ██▄▄▄   ██   
     ▀▀ 
```

**QuaNet — a quantum-secured network for communication anywhere on any signal**

QuaNet aims to prove that ordinary consumer devices —
uncooled mobile handsets, desktops, whatever is in a pocket or on a desk — can
establish peer-to-peer cryptographic trust directly without a central authority issuing keys and without
trusting any carrier in the middle.

The end goal is to use **readily available signal — maybe SMS, maybe photonic, whatever** —
as the carrier. Today the photonic path is implemented (camera photonic);
the microwave/SMS path is specified here - https://zenodo.org/records/24096009

---

## Brief

https://zenodo.org/records/24058195

---

## Install

```bash
npm install clasp-photonic-pairing
```

---

## Quick Start (Browser / PWA)

```typescript
import {
  PhotonicQuantumAnalyzer,
  imageBitmapToGrayscaleArray,
} from 'clasp-photonic-pairing';

async function pairDevices() {
  // 1. Request camera access
  const stream = await navigator.mediaDevices.getUserMedia({ video: true });
  const track = stream.getVideoTracks()[0];
  const imageCapture = new ImageCapture(track);

  // 2. Capture two photos 33ms apart (~30fps)
  const bitmap1 = await imageCapture.grabFrame();
  await new Promise((r) => setTimeout(r, 33));
  const bitmap2 = await imageCapture.grabFrame();
  track.stop();

  // 3. Convert to grayscale arrays
  const arr1 = await imageBitmapToGrayscaleArray(bitmap1);
  const arr2 = await imageBitmapToGrayscaleArray(bitmap2);

  // 4. Analyze photonic differences
  const analyzer = new PhotonicQuantumAnalyzer();
  const result = analyzer.analyzePhotoPair(arr1, arr2, 33.3);

  console.log('Photonic digest:', result.photonicDigest);
  console.log('Authentic:', result.isQuantumAuthentic);

  // 5. Use result.photonicDigest as seed for your pairwise passkey
  //    e.g. SHA-256(digest + peerId + sessionId)
}
```

---

## API

### `PhotonicQuantumAnalyzer`

```typescript
const analyzer = new PhotonicQuantumAnalyzer(activeDims = 4, numZeros = 16);
```

| Option | Default | Description |
|---|---|---|
| `activeDims` | `4` | Number of active Hilbert dimensions |
| `numZeros` | `16` | Number of Riemann zeros (γₙ) to use |

### `analyzer.analyzePhotoPair(img1, img2, deltaTMs = 33.3)`

Compares two grayscale image arrays (`number[][]`, values 0–255) and returns:

| Field | Type | Description |
|---|---|---|
| `photonicDigest` | `string` | 256-bit hex digest (64 chars) |
| `hilbertChordalDistance` | `number` | Hilbert space distance between frames |
| `kottmanPackingLimit` | `number` | ~0.4142 (Kottman radius) |
| `filteredTunnelingRatio` | `number` | 0–1 ratio of resonant tunneling samples |
| `isQuantumAuthentic` | `boolean` | Passes Kottman boundary + tunneling check |
| `totalSamples` | `number` | Number of pixel samples analyzed |

### Helper: `imageBitmapToGrayscaleArray(bitmap)`

Converts an `ImageBitmap` to a `number[][]` grayscale array (0–255) using standard luminance weighting.

### Helper: `sha256Hex(data: Uint8Array)`

Built-in FIPS 180-4 SHA-256 implementation. Used to condense the Hilbert accumulator into the final 256-bit digest.

### `EntropyCryptoPool` (desktop / Node — no camera)

```typescript
import { entropyCryptoPool } from 'clasp-photonic-pairing';

// Pool accumulates live entropy from app start
entropyCryptoPool.start();

// At invite acceptance: condense to a one-time 64-hex digest
// (same format as the mobile dual-photo photonic digest)
const { digest, samples, sources } = entropyCryptoPool.condenseWithStats(24);
```

The desktop counterpart to the mobile dual-photo capture. Mixes timer jitter
(monotonic vs wall-clock drift), event-loop scheduling lag, human interaction
timing (timing only — never key content), machine state, and a CSPRNG
contribution, condensed with SHA-256. Designed for co-signing flows where one
side has no camera: at invite acceptance the mobile side contributes two photos
33ms apart and the desktop side contributes its pool digest; both digests are
combined into the shared signing/encryption key.

---

## ⚠️ Caveats

### 1. Experimental Cryptography — Not Formally Analyzed

This is **custom cryptography**.  Has **not undergone formal cryptanalysis**.

For high-security production systems, **do not use this as the sole cipher**. Wrap it inside a proven cipher such as **AES-GCM** or **ChaCha20-Poly1305**. Treat this as an obfuscation / key-material derivation layer, not a standalone encryption standard.

### 2. Camera Permission Required

The device must grant camera access (`navigator.mediaDevices.getUserMedia({ video: true })`). The operating system will display a permission prompt. There is **no silent backdoor** to the camera sensor.

### 3. Digest Uniqueness

There is **no way to create an identical lighting scenario, ever**. Quantum mechanics governs photon emission and absorption at the sensor level; shot noise, thermal variance, and sub-pixel alignment ensure that two sequential photos will never produce identical digests.

### 4. SHA-256 Is Still Present

SHA-256 is used as the final digest condensation step. This is intentional: post-quantum security stacks **on top of** modern cryptography, it does not replace it outright. A 256-bit digest retains approximately 128 bits of post-quantum security against Grover's algorithm preimage attacks, requiring roughly 2¹²⁸ quantum evaluations.

### 5. SMS-Band Signing Is Theoretical

The Continuous-Variable (CV-QIP/CV-QDS) protocol described in the whitepaper
above is a specification, not an implemented feature of this library. No
microwave quadrature modulation, heterodyne detection, or LDPC
reconciliation is performed by this package. See the QuaNet roadmap.

---

## License

**Clasp Photonic Pairing License**

Copyright © 2026 ClaspOS

Permission is hereby granted, free of charge, to any individual or small business (defined as an entity with fewer than 50 employees and less than $1,000,000 USD in annual gross revenue) to use, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

**Enterprise Use:** Entities with 50 or more employees, or annual gross revenue of $1,000,000 USD or more, **must obtain a separate commercial license** before using this software in any capacity. Contact the rights holder for enterprise licensing terms.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Roadmap

### QuaNet milestones

- [x] Photonic entropy source (mobile dual-photo capture)
- [x] Entropy crypto pool (desktop / Node, no camera)
- [x] Invite-acceptance co-signing (both sides contribute entropy at acceptance)
- [ ] Signal-carrier abstraction: pluggable entropy sources (photonic, RF, other)
- [ ] CV-QDS quadrature modulation over sub-6 GHz SDR (whitepaper §2)
- [ ] Thermal parameter estimation (`τ`, `ξ`) and Holevo-bound checking (whitepaper §3)
- [ ] LDPC reverse reconciliation + Toeplitz privacy amplification
- [ ] SMS-band application signing pilot between two handsets

### Library milestones

- [ ] Node.js / non-browser build target (camera stub for testing)
- [ ] WASM port of the Riemann filter for performance
- [ ] Optional AES-GCM wrapper for production use
- [ ] Cross-platform mobile (React Native, Flutter) bridge

---

## Contact

Questions about enterprise licensing: contact the repository owner - karlroescharchitecture@gmail.com
