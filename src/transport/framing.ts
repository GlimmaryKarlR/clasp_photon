/**
 * Binary transport framing shared by every QuaNet carrier.
 *
 * Layout (network byte order):
 *
 *   offset  size  field
 *   0       2     magic 'Q','P'
 *   2       1     version (1)
 *   3       1     frame type
 *   4       1     flags
 *   5       4     session id
 *   9       4     message id
 *   13      2     fragment index
 *   15      2     fragment count
 *   17      2     payload length
 *   19      3     reserved (zero)
 *   22      N     payload
 *   22+N    4     CRC-32 of header + payload
 *
 * The 22-byte header is deliberately carrier-neutral: the same bytes travel
 * through an LDPC-coded RGB frame or a Base85 SMS segment. Fragmentation and
 * reassembly preserve session state because every fragment carries the
 * session and message identifiers.
 */

import { concatBytes } from '../util/bits.js';

export const FRAME_MAGIC = [0x51, 0x50] as const; // "QP"
export const FRAME_VERSION = 1;
export const FRAME_HEADER_BYTES = 22;
export const FRAME_CRC_BYTES = 4;
export const FRAME_OVERHEAD_BYTES = FRAME_HEADER_BYTES + FRAME_CRC_BYTES;
export const MAX_FRAME_PAYLOAD = 0xffff;

export enum FrameType {
  HandshakeInit = 1,
  HandshakeResponse = 2,
  Data = 3,
  Ack = 4,
  Close = 5,
}

export enum FrameFlags {
  None = 0,
  /** Final fragment of a message. */
  Last = 1 << 0,
  /** Sender requests an acknowledgement. */
  NeedsAck = 1 << 1,
}

export interface Frame {
  type: FrameType;
  flags: number;
  sessionId: number;
  messageId: number;
  fragmentIndex: number;
  fragmentCount: number;
  payload: Uint8Array;
}

export interface FrameEncodeOptions {
  sessionId?: number;
  messageId?: number;
  fragmentIndex?: number;
  fragmentCount?: number;
  flags?: number;
}

/** CRC-32 (IEEE 802.3), reflected polynomial 0xEDB88320. */
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** Encode a frame into header + payload + CRC. */
export function encodeFrame(frame: Frame): Uint8Array {
  const payload = frame.payload;
  if (payload.length > MAX_FRAME_PAYLOAD) {
    throw new Error(`payload exceeds ${MAX_FRAME_PAYLOAD} bytes`);
  }
  const buffer = new Uint8Array(FRAME_HEADER_BYTES + payload.length + FRAME_CRC_BYTES);
  const view = new DataView(buffer.buffer);
  buffer[0] = FRAME_MAGIC[0];
  buffer[1] = FRAME_MAGIC[1];
  buffer[2] = FRAME_VERSION;
  buffer[3] = frame.type & 0xff;
  buffer[4] = frame.flags & 0xff;
  view.setUint32(5, frame.sessionId >>> 0, false);
  view.setUint32(9, frame.messageId >>> 0, false);
  view.setUint16(13, frame.fragmentIndex & 0xffff, false);
  view.setUint16(15, frame.fragmentCount & 0xffff, false);
  view.setUint16(17, payload.length, false);
  // bytes 19..21 reserved
  buffer.set(payload, FRAME_HEADER_BYTES);
  const crc = crc32(buffer.subarray(0, FRAME_HEADER_BYTES + payload.length));
  view.setUint32(FRAME_HEADER_BYTES + payload.length, crc, false);
  return buffer;
}

export interface DecodedFrame extends Frame {
  /** Total bytes consumed, including CRC. Trailing padding is ignored. */
  frameBytes: number;
}

/**
 * Parse and validate a frame. Trailing bytes (for example optical padding to
 * the LDPC block size) are ignored. Throws on malformed input.
 */
export function decodeFrame(bytes: Uint8Array): DecodedFrame {
  if (bytes.length < FRAME_OVERHEAD_BYTES) throw new Error('frame too short');
  if (bytes[0] !== FRAME_MAGIC[0] || bytes[1] !== FRAME_MAGIC[1]) {
    throw new Error('bad frame magic');
  }
  if (bytes[2] !== FRAME_VERSION) throw new Error(`unsupported frame version ${bytes[2]}`);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const payloadLength = view.getUint16(17, false);
  const total = FRAME_HEADER_BYTES + payloadLength + FRAME_CRC_BYTES;
  if (bytes.length < total) throw new Error('truncated frame');
  const expected = view.getUint32(FRAME_HEADER_BYTES + payloadLength, false);
  const actual = crc32(bytes.subarray(0, FRAME_HEADER_BYTES + payloadLength));
  if (expected !== actual) throw new Error('frame CRC mismatch');

  return {
    type: view.getUint8(3) as FrameType,
    flags: view.getUint8(4),
    sessionId: view.getUint32(5, false),
    messageId: view.getUint32(9, false),
    fragmentIndex: view.getUint16(13, false),
    fragmentCount: view.getUint16(15, false),
    payload: bytes.slice(FRAME_HEADER_BYTES, FRAME_HEADER_BYTES + payloadLength),
    frameBytes: total,
  };
}

/** Non-throwing decode for lossy carriers. */
export function tryDecodeFrame(bytes: Uint8Array): DecodedFrame | null {
  try {
    return decodeFrame(bytes);
  } catch {
    return null;
  }
}

/** Build one frame from an already-sized payload. */
export function buildFrame(
  type: FrameType,
  payload: Uint8Array,
  options: FrameEncodeOptions = {}
): Uint8Array {
  return encodeFrame({
    type,
    flags: options.flags ?? 0,
    sessionId: options.sessionId ?? 0,
    messageId: options.messageId ?? 0,
    fragmentIndex: options.fragmentIndex ?? 0,
    fragmentCount: options.fragmentCount ?? 1,
    payload,
  });
}

export interface FragmentOptions {
  sessionId?: number;
  messageId?: number;
  maxPayloadBytes: number;
  flags?: number;
}

/**
 * Split a message into frames. Every fragment gets the same session and
 * message id, so a receiver can reassemble across reordering or carrier
 * switching.
 */
export function fragmentMessage(
  type: FrameType,
  payload: Uint8Array,
  options: FragmentOptions
): Uint8Array[] {
  const maxPayload = Math.max(1, Math.min(MAX_FRAME_PAYLOAD, Math.floor(options.maxPayloadBytes)));
  const count = Math.max(1, Math.ceil(payload.length / maxPayload));
  if (count > 0xffff) throw new Error('message needs too many fragments');
  const frames: Uint8Array[] = [];
  for (let index = 0; index < count; index++) {
    const start = index * maxPayload;
    const end = Math.min(payload.length, start + maxPayload);
    const isLast = index === count - 1;
    const flags = (options.flags ?? 0) | (isLast ? FrameFlags.Last : 0);
    frames.push(
      buildFrame(type, payload.subarray(start, end), {
        sessionId: options.sessionId,
        messageId: options.messageId,
        fragmentIndex: index,
        fragmentCount: count,
        flags,
      })
    );
  }
  return frames;
}

export interface ReassembledMessage {
  type: FrameType;
  sessionId: number;
  messageId: number;
  payload: Uint8Array;
  fragments: number;
}

interface Bucket {
  type: FrameType;
  fragmentCount: number;
  parts: Map<number, Uint8Array>;
  bytes: number;
  createdAt: number;
  updatedAt: number;
}

export interface ReassemblerOptions {
  /** Drop incomplete messages after this age. Default 30 s. */
  timeoutMs?: number;
  /** Maximum accepted message size. Default 1 MiB. */
  maxMessageBytes?: number;
}

/**
 * Reassembles fragmented messages keyed by (sessionId, messageId). Handles
 * duplicates, out-of-order arrival and carrier switches. Completed messages
 * are returned once; inconsistent fragments are ignored.
 */
export class Reassembler {
  private readonly buckets = new Map<string, Bucket>();
  private readonly timeoutMs: number;
  private readonly maxMessageBytes: number;

  constructor(options: ReassemblerOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.maxMessageBytes = options.maxMessageBytes ?? 1024 * 1024;
  }

  add(frame: Frame, now = Date.now()): ReassembledMessage | null {
    if (frame.fragmentCount <= 0 || frame.fragmentCount > 0xffff) return null;
    if (frame.fragmentIndex < 0 || frame.fragmentIndex >= frame.fragmentCount) return null;

    const key = `${frame.sessionId}:${frame.messageId}`;
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = {
        type: frame.type,
        fragmentCount: frame.fragmentCount,
        parts: new Map(),
        bytes: 0,
        createdAt: now,
        updatedAt: now,
      };
      this.buckets.set(key, bucket);
    }
    if (bucket.fragmentCount !== frame.fragmentCount || bucket.type !== frame.type) {
      // Conflicting metadata: treat as a new/foreign message and ignore.
      return null;
    }
    if (bucket.parts.has(frame.fragmentIndex)) return null;
    if (bucket.bytes + frame.payload.length > this.maxMessageBytes) {
      this.buckets.delete(key);
      return null;
    }

    bucket.parts.set(frame.fragmentIndex, frame.payload.slice());
    bucket.bytes += frame.payload.length;
    bucket.updatedAt = now;

    if (bucket.parts.size !== bucket.fragmentCount) return null;

    const ordered: Uint8Array[] = [];
    for (let i = 0; i < bucket.fragmentCount; i++) {
      const part = bucket.parts.get(i);
      if (!part) return null;
      ordered.push(part);
    }
    this.buckets.delete(key);
    return {
      type: bucket.type,
      sessionId: frame.sessionId,
      messageId: frame.messageId,
      payload: concatBytes(...ordered),
      fragments: bucket.fragmentCount,
    };
  }

  /** Add a raw encoded frame. Returns a message when this completes one. */
  addBytes(bytes: Uint8Array, now = Date.now()): ReassembledMessage | null {
    const frame = tryDecodeFrame(bytes);
    return frame ? this.add(frame, now) : null;
  }

  /** Remove stale incomplete messages. Returns the number dropped. */
  expire(now = Date.now()): number {
    let dropped = 0;
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.updatedAt > this.timeoutMs) {
        this.buckets.delete(key);
        dropped++;
      }
    }
    return dropped;
  }

  pendingCount(): number {
    return this.buckets.size;
  }

  clear(): void {
    this.buckets.clear();
  }
}

/** Convenience one-shot reassembly (tests, offline decoding). */
export function reassembleFrames(frames: Frame[]): ReassembledMessage | null {
  const reassembler = new Reassembler();
  let result: ReassembledMessage | null = null;
  for (const frame of frames) {
    const message = reassembler.add(frame);
    if (message) result = message;
  }
  return result;
}
