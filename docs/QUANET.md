# QuaNet baseline architecture

QuaNet is a carrier-agnostic secure session layer for ordinary consumer
devices. The design goal is simple: derive and use post-quantum keys without a
central authority, then move the same encrypted records over whatever signal is
available — a camera-based lighting comparison and SMS text today, or a
future RF/photonic byte link.

The implementation in this repository is the **baseline**: the session,
framing and carrier layers are present, tested, and dependency-free. It is
deliberately small enough to audit and portable enough to run in a browser,
Node, or bare-metal Rust. It is not a certified cryptographic product.

```
┌─────────────────────────────────────────────────────────────┐
│ application                                                 │
├─────────────────────────────────────────────────────────────┤
│ QuaNetSession                                               │
│   ML-KEM-768 handshake → directional SHAKE256 keys          │
│   ChaCha20-Poly1305 records + 64-record replay window       │
├─────────────────────────────────────────────────────────────┤
│ framing                                                     │
│   22-byte header + payload + CRC-32                         │
│   fragmentation / reassembly, session id on every fragment │
├─────────────────────────────────────────────────────────────┤
│ carrier abstraction                                         │
│   photonic link │ SMS Base85 │ multipath failover           │
├─────────────────────────────────────────────────────────────┤
│ physical signal: camera lighting / display / SMS            │
└─────────────────────────────────────────────────────────────┘
```

The cryptographic session is independent of the carrier. Carriers only move
opaque frame bytes. That is what lets a message start on one carrier and finish
on another without renegotiating keys.

---

## Phase 1 — native post-quantum core

### TypeScript reference (`src/crypto/`)

| Module | Purpose |
|---|---|
| `keccak.ts` | SHA3-256, SHA3-512, SHAKE128, SHAKE256 |
| `poly.ts` | Kyber ring arithmetic, NTT, sampling, polynomial encoding |
| `mlkem.ts` | ML-KEM-768 keygen, encapsulation, decapsulation |
| `chacha20poly1305.ts` | RFC 8439 AEAD used for session records |

The TypeScript implementation is the portable reference. It is used directly
in browsers and Node and is the byte-for-byte oracle for the native core.

### Rust core (`native/`)

- Zero external crates and `no_std` for non-test builds.
- Keccak, polynomial/NTT arithmetic, and ML-KEM implemented from scratch.
- Exposed as an `rlib` with a C ABI (`clasp_photon_keygen`,
  `clasp_photon_encaps`, `clasp_photon_decaps`) and a small CLI used by the
  cross-check.
- `native/wasm/` is a separate `cdylib` with a statics-based ABI, so the core
  stays allocation-free. The built artifact is copied to
  `dist/clasp_photon_wasm.wasm`.

ML-KEM parameters match Kyber-768 / ML-KEM-768: 1184-byte public key,
2400-byte secret key, 1088-byte ciphertext, 32-byte shared secret. Deterministic
key generation derives the implicit-rejection value as
`z = SHA3-256(seed || 0x5a)`; the deterministic seed options exist for tests and
cross-checks and are not a production entropy source.

The scalar NTT is the current baseline. AVX2 and NEON kernels are planned; the
portable implementation remains the correctness reference.

```bash
npm run build:native   # cargo tests, host build, wasm build
npm run crosscheck     # byte-for-byte Rust/WASM ↔ TypeScript ML-KEM check
```

---

## Phase 2 — camera sensor control

`src/sensor/cameraSensor.ts` builds and applies manual media-track constraints:

- exposure mode and exposure time,
- ISO / gain,
- manual focus distance,
- white balance and colour temperature,
- fixed frame rate and rear-camera selection.

`FrameClock` records capture timestamps, measured intervals, FPS, and jitter so
a receiver can detect dropped or torn captures. Browser APIs are touched lazily so the pure constraint
and clock logic runs in Node tests.

---

## Phase 3 — optical utilities (retained, not on the carrier path)

Spatial RGB rendering and image decoding were removed. Sequential captures are
compared for lighting and sensor entropy; image content is not treated as data.
Two derived utilities remain available for future work:

- `src/optical/perspective.ts` — four-point homography estimation/inversion,
  bilinear warping, planar PnP pose decomposition, maximum inscribed circle,
  and polygon containment.
- `src/optical/fec.ts` — a systematic LDPC baseline
  (`k=2048`, `m=1024`, `n=3072`) with offset min-sum decoding.

Neither module is used by `PhotonicCarrier`. The carrier treats its physical
link as an opaque byte channel; the retained utilities are experimental
building blocks, not a claim that data is hidden in pixels.

---

## Phase 4 — carrier-agnostic transport and session

### Frame format

`src/transport/framing.ts` uses a carrier-neutral frame:

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | magic `QP` |
| 2 | 1 | version |
| 3 | 1 | frame type |
| 4 | 1 | flags |
| 5 | 4 | session id |
| 9 | 4 | message id |
| 13 | 2 | fragment index |
| 15 | 2 | fragment count |
| 17 | 2 | payload length |
| 19 | 3 | reserved (zero) |
| 22 | N | payload |
| 22+N | 4 | CRC-32 of header + payload |

`FrameType` distinguishes handshake init/response, data, ack, and close. The
`Last` and `NeedsAck` flags support fragmentation and acknowledgement.
Fragmentation is done at the smallest common carrier payload size, so any
fragment can fail over to any carrier. Every fragment carries the session and
message ids, so reassembly — and session state — survives a mid-message carrier
switch.

### Carriers (`src/transport/carriers.ts`)

| Carrier | Wire form | Payload budget |
|---|---|---|
| Photonic | opaque display/capture frame link | 230 bytes/frame |
| SMS | `QP1:` + Base85 (85-character alphabet) | 80 bytes/frame, 140 chars max |
| Loopback | in-process frame delivery | configurable; deterministic loss/corruption |
| Multipath | ordered failover across carriers | smallest common payload |

`MultipathTransport` sends each frame through the first available carrier,
retries the next on failure, and reassembles messages regardless of which
carrier delivered the final fragment.

### Session (`src/session/quanetSession.ts`)

```
initiator                                      responder
(pk, sk) ← ML-KEM keygen
pk                       ────────────────────▶
                                               ct, ss ← Encapsulate(pk)
                                               transcript = SHA3-256(pk || ct)
                         ◀──────────────────── ct || confirm(ss, transcript)
ss ← Decapsulate(sk, ct)
verify confirm
```

Both ends derive independent initiator→responder and responder→initiator keys
with SHAKE256. Records use a 12-byte nonce (4-byte direction prefix + 8-byte
counter) and ChaCha20-Poly1305. Nonces travel with each record, so carriers do
not need to preserve record order. The receiver enforces a 64-record replay
window, rejects wrong-direction nonces, and authenticates the session id as
associated data.

---

## Security properties and limits

**Provided by the baseline**

- Post-quantum confidentiality against a passive adversary during key exchange
  (ML-KEM-768 construction) and in record encryption (ChaCha20-Poly1305).
- Fresh ephemeral ML-KEM key pair per handshake, so recorded traffic is not
  decryptable by a later compromise of long-term secrets, provided session
  keys are discarded.
- Per-direction keys and nonces, record authentication, and replay rejection.
- Transport corruption detection (CRC-32).

**Not provided**

- **Authentication.** The handshake is unauthenticated by default. An active
  man-in-the-middle can substitute its own ML-KEM public key. Pin an
  out-of-band fingerprint (`fingerprintPublicKey`) or layer an authenticated
  protocol on top.
- **Formal validation.** The ML-KEM implementation is construction-compatible
  but has not passed FIPS 203 validation or KAT review. The LDPC code is a
  custom baseline, not a standardized code.
- **Physical-layer quantum key distribution.** The CV-QIP/CV-QDS microwave
  specification is not implemented here. The SMS carrier is an application-layer
  transport over ordinary SMS text, not a quantum channel.

Custom cryptography is experimental. Do not use it as the sole protection for
high-value production traffic without independent review.

---

## Verification

```bash
npm test          # build + full TypeScript test suite
npm run verify    # build, native tests/build, cross-check, full test suite
```

The TypeScript suite covers SHA-3/SHAKE vectors, RFC 8439 AEAD vectors, ML-KEM
round-trips, camera constraints and frame-clock statistics, the retained
homography/PnP/MIC and LDPC utilities, Base85/framing/fragmentation, carrier
failover, the session handshake, tamper/replay rejection, and encrypted
end-to-end transfers over SMS and the photonic byte link.

---

## Roadmap

- [x] Native PQ core (Rust `no_std`, Keccak, NTT, ML-KEM; TS reference; WASM)
- [x] Manual camera sensor control and refresh-locked frame clock
- [x] Optical geometry/FEC utilities retained as standalone modules
- [x] Sequential-photo lighting/sensor entropy comparison (legacy pairing path)
- [x] Carrier abstraction, SMS/photonic byte link, fragmentation and failover
- [x] ML-KEM handshake and ChaCha20-Poly1305 session records
- [ ] Authenticated handshake (fingerprint pinning / QR-bound identity)
- [ ] AVX2 and NEON NTT kernels
- [ ] FIPS 203 KATs and external cryptographic review
- [ ] Retire or repurpose unused optical utilities
- [ ] Real-handset camera calibration and capture pipeline
- [ ] CV-QIP/CV-QDS physical-layer pilot over sub-6 GHz SDR
