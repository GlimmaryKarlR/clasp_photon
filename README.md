# clasp_photon

**Post-quantum encryption**

No external cryptographic dependencies. Rust `no_std` core, TypeScript
reference implementation, and a dependency-free carrier stack for photonic and
SMS transport.

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
as the carrier. The baseline here implements two concrete carriers: a
**photonic** path (screen-rendered RGB frames captured by a camera) and an
**SMS** path (framed bytes encoded as Base85 text). The same encrypted session
can fragment across either, or fail over between them mid-message.

The physical-layer microwave/CV-QIP path remains a specification:
https://zenodo.org/records/24096009

### Baseline implementation

| Phase | Layer | Code | Status |
|---|---|---|---|
| 1 | Native PQ core | `native/` (Rust `no_std`), `src/crypto/` (TS reference) | ML-KEM-768, SHA-3/SHAKE, NTT, ChaCha20-Poly1305; Rust ↔ TS byte-for-byte cross-check |
| 2 | Camera sensor | `src/sensor/cameraSensor.ts` | Manual ISO/exposure/focus/white balance, refresh-locked frame clock |
| 3 | Spatial optical | `src/optical/` | 32×32×3 RGB frame, LDPC baseline, homography/PnP/MIC perspective correction |
| 4 | Transport + session | `src/transport/`, `src/session/` | Base85 SMS and photonic carriers, fragmentation/failover, ML-KEM handshake, AEAD records |

Full architecture, wire formats, and security limits: [`docs/QUANET.md`](docs/QUANET.md).

---

## Native core

The cryptographic core is also implemented in Rust with **zero external
crates** and `#![no_std]` for non-test builds. It ships as an `rlib` with a C
ABI and as a separate wasm32 `cdylib`.

```bash
npm run build:native   # cargo tests, host rlib/CLI, wasm32 artifact
npm run crosscheck     # byte-for-byte Rust/WASM ↔ TypeScript ML-KEM check
npm test               # TypeScript build + full test suite
npm run verify         # all of the above
```

The TypeScript implementation remains the portable reference and is used
directly by browser/Node consumers. The native core is the path toward
bare-metal, constrained devices, and future AVX2/NEON NTT kernels (currently
scalar).

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

## QuaNet baseline API

### Encrypted session

```typescript
import {
  InitiatorHandshake,
  ResponderHandshake,
} from 'clasp-photonic-pairing';

// Initiator
const initiator = InitiatorHandshake.create();
const initMessage = initiator.message(); // send 1184-byte public key

// Responder
const responder = ResponderHandshake.accept(initMessage);
const response = responder.response; // send 1088-byte ct + 16-byte confirm

// Initiator completes
const session = initiator.complete(response);

// Either side encrypts records. The nonce travels with the record.
const record = session.encryptText('hello');
const plaintext = responder.session.decryptText(record);
```

`establishLocalSession()` runs both sides in one process for tests and
simulations. `fingerprintPublicKey()` returns a stable SHA3-256 fingerprint for
out-of-band pinning.

### Carriers

```typescript
import {
  MultipathTransport,
  createSmsLoopbackPair,
  PhotonicCarrier,
  FrameType,
} from 'clasp-photonic-pairing';

const [smsA, smsB] = createSmsLoopbackPair();
const sender = new MultipathTransport([smsA]);
const receiver = new MultipathTransport([smsB]);

receiver.onMessage(async (message) => {
  console.log(responder.session.decryptText(message.payload));
});

await sender.sendMessage(FrameType.Data, record, { sessionId: session.sessionId });
```

`PhotonicCarrier` takes a `{ display, capture }` link. `MultipathTransport`
fragments at the smallest common payload, retries across carriers, and
reassembles messages even when different carriers deliver different fragments.

### Spatial optical frame

```typescript
import {
  renderSpatialFrame,
  decodeSpatialFrame,
} from 'clasp-photonic-pairing';

const frame = renderSpatialFrame(codewordBits); // 320×320 RGB image
// ... the receiver captures the displayed frame ...
const decoded = decodeSpatialFrame(capturedImage, tryDecode);
```

`codewordBits` is one 3072-bit LDPC codeword (`defaultLdpcCode.encode`).
`decodeSpatialFrame` locates the four finders, rectifies perspective, samples
the 32×32×3 payload, thresholds each channel, and lets the supplied callback
validate candidate windings.

---

## ⚠️ Caveats

### 1. Experimental Cryptography — Not Formally Analyzed

This is **custom cryptography**. It has **not undergone formal cryptanalysis**
and the ML-KEM implementation, while construction-compatible with Kyber-768 /
ML-KEM-768, has **not passed FIPS 203 validation or KAT review**. The LDPC code
is a custom baseline, not a standardized code.

For high-security production systems, **do not use this as the sole cipher**.
Wrap it inside a proven cipher such as **AES-GCM** or **ChaCha20-Poly1305**.
Treat this as an obfuscation / key-material derivation layer, not a standalone
encryption standard.

The QuaNet handshake is also **unauthenticated by default**: it protects
against a passive quantum-capable adversary, but an active man-in-the-middle
can substitute its own public key. Pin `fingerprintPublicKey()` out of band or
layer an authenticated protocol on top.

### 2. Camera Permission Required

The device must grant camera access (`navigator.mediaDevices.getUserMedia({ video: true })`). The operating system will display a permission prompt. There is **no silent backdoor** to the camera sensor.

### 3. Digest Uniqueness

There is **no way to create an identical lighting scenario, ever**. Quantum mechanics governs photon emission and absorption at the sensor level; shot noise, thermal variance, and sub-pixel alignment ensure that two sequential photos will never produce identical digests.

### 4. SHA-256 Is Still Present

SHA-256 is used as the final digest condensation step in the legacy photonic
pairing path. This is intentional: post-quantum security stacks **on top of**
modern cryptography, it does not replace it outright. A 256-bit digest retains
approximately 128 bits of post-quantum security against Grover's algorithm
preimage attacks, requiring roughly 2¹²⁸ quantum evaluations.

### 5. SMS Carrier Is Application-Layer

The QuaNet SMS carrier moves framed, encrypted bytes as Base85 text inside
ordinary SMS messages. The Continuous-Variable (CV-QIP/CV-QDS) physical-layer
protocol in the whitepaper above is still a specification: no microwave
quadrature modulation, heterodyne detection, or quantum-channel reconciliation
is performed by this package. See the QuaNet roadmap.

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
- [x] Native post-quantum core (Rust `no_std`: Keccak, NTT, ML-KEM; TS reference; WASM)
- [x] Manual camera sensor control and refresh-locked frame clock
- [x] Spatial RGB modulation, LDPC baseline, perspective/PnP correction
- [x] Carrier abstraction: photonic, SMS, loopback, multipath failover
- [x] Fragmentation/reassembly preserving session state across carriers
- [x] ML-KEM handshake and ChaCha20-Poly1305 session records
- [ ] Authenticated handshake (fingerprint pinning / QR-bound identity)
- [ ] AVX2 and NEON NTT kernels
- [ ] FIPS 203 KATs and external cryptographic review
- [ ] Generalized LDPC (GLDPC) spatial code
- [ ] Real-handset camera calibration and capture pipeline
- [ ] CV-QDS quadrature modulation over sub-6 GHz SDR (whitepaper §2)
- [ ] Thermal parameter estimation (`τ`, `ξ`) and Holevo-bound checking (whitepaper §3)
- [ ] LDPC reverse reconciliation + Toeplitz privacy amplification
- [ ] SMS-band application signing pilot between two handsets

### Library milestones

- [x] Node.js / non-browser build target (camera stub for testing)
- [x] WASM build of the native core
- [ ] WASM port of the Riemann filter for performance
- [ ] Optional AES-GCM wrapper for production use
- [ ] Cross-platform mobile (React Native, Flutter) bridge

---

## Contact

Questions about enterprise licensing: contact the repository owner - karlroescharchitecture@gmail.com
