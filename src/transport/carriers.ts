/**
 * Carrier abstraction for QuaNet.
 *
 * A `Carrier` moves opaque framed bytes. The photonic carrier passes frames
 * over an abstract display/capture link; the SMS carrier maps frames to Base85
 * text. `MultipathTransport` runs both at once, fragments at the smallest
 * common payload size and reassembles independently of which carrier delivered
 * a fragment. Session state lives in the frame header, so switching carriers
 * mid-message does not disturb the cryptographic session.
 */

import { xorshift32 } from '../util/bits.js';
import {
  FrameFlags,
  FrameType,
  Reassembler,
  type ReassembledMessage,
  fragmentMessage,
  tryDecodeFrame,
} from './framing.js';
import {
  SMS_BASE85_ALPHABET,
  base85Decode,
  base85Encode,
} from './base85.js';

export interface Carrier {
  readonly name: string;
  /** Maximum frame payload this carrier can move in one go. */
  readonly maxPayloadBytes: number;
  send(frame: Uint8Array): Promise<void>;
  onReceive(handler: (frame: Uint8Array) => void): () => void;
  close(): Promise<void>;
  available?(): boolean;
}

/* ------------------------------------------------------------------ */
/* Loopback carrier (tests, local IPC, deterministic simulations)      */
/* ------------------------------------------------------------------ */

export interface LoopbackOptions {
  maxPayloadBytes?: number;
  /** Probability [0,1] that a frame is silently dropped. */
  dropRate?: number;
  /** Probability [0,1] that a frame is corrupted. */
  corruptRate?: number;
  seed?: number;
}

export class LoopbackCarrier implements Carrier {
  readonly name: string;
  readonly maxPayloadBytes: number;
  peer: LoopbackCarrier | null = null;
  private handlers = new Set<(frame: Uint8Array) => void>();
  private random: () => number;
  private dropRate: number;
  private corruptRate: number;
  private closed = false;

  constructor(name = 'loopback', options: LoopbackOptions = {}) {
    this.name = name;
    this.maxPayloadBytes = options.maxPayloadBytes ?? 230;
    this.dropRate = options.dropRate ?? 0;
    this.corruptRate = options.corruptRate ?? 0;
    this.random = xorshift32(options.seed ?? 0x1234abcd);
  }

  async send(frame: Uint8Array): Promise<void> {
    if (this.closed) throw new Error(`${this.name} is closed`);
    if (!this.peer) throw new Error(`${this.name} has no peer`);
    if (this.random() / 0x100000000 < this.dropRate) return;
    let outbound = frame;
    if (this.random() / 0x100000000 < this.corruptRate && frame.length > 0) {
      outbound = frame.slice();
      const bit = Math.floor((this.random() / 0x100000000) * outbound.length * 8);
      outbound[bit >> 3] ^= 1 << (bit & 7);
    }
    this.peer.deliver(outbound);
  }

  /** Deliver bytes as if they arrived from the peer. */
  deliver(frame: Uint8Array): void {
    if (this.closed) return;
    for (const handler of [...this.handlers]) handler(frame.slice());
  }

  onReceive(handler: (frame: Uint8Array) => void): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  async close(): Promise<void> {
    this.closed = true;
    this.handlers.clear();
  }
}

export function createLoopbackPair(
  options: LoopbackOptions = {}
): [LoopbackCarrier, LoopbackCarrier] {
  const a = new LoopbackCarrier('loopback-a', { ...options, seed: (options.seed ?? 1) + 1 });
  const b = new LoopbackCarrier('loopback-b', { ...options, seed: (options.seed ?? 1) + 2 });
  a.peer = b;
  b.peer = a;
  return [a, b];
}

/* ------------------------------------------------------------------ */
/* Photonic carrier: framed bytes over an abstract physical link       */
/* ------------------------------------------------------------------ */

export interface PhotonicLink {
  /** Publish one complete frame to the physical channel. */
  display(frame: Uint8Array, durationMs?: number): Promise<void> | void;
  /** Return the next complete frame, or null when nothing is available. */
  capture(): Promise<Uint8Array | null> | Uint8Array | null;
  close?(): Promise<void> | void;
}

export interface PhotonicCarrierOptions {
  link: PhotonicLink;
  /** Time the link keeps a frame available to the receiver. */
  frameDurationMs?: number;
}

/** Upper bound for one photonic-link frame. */
export const PHOTONIC_FRAME_BYTES = 256;
export const PHOTONIC_MAX_PAYLOAD_BYTES = PHOTONIC_FRAME_BYTES - 22 - 4;

/**
 * Moves framed bytes over an arbitrary display/capture link.
 *
 * The carrier deliberately does not inspect image content. In the legacy
 * pairing path, two photos 33 ms apart are compared for lighting/sensor
 * entropy (`photonicQuantumAnalyzer.ts`); nothing in the image is decoded as
 * data. A future photonic, RF, or file link only needs to deliver exact frame
 * bytes through `display` and `capture`.
 */
export class PhotonicCarrier implements Carrier {
  readonly name = 'photonic';
  readonly maxPayloadBytes = PHOTONIC_MAX_PAYLOAD_BYTES;
  private handlers = new Set<(frame: Uint8Array) => void>();
  private readonly link: PhotonicLink;
  private readonly frameDurationMs: number;
  private closed = false;

  constructor(options: PhotonicCarrierOptions) {
    this.link = options.link;
    this.frameDurationMs = options.frameDurationMs ?? 100;
  }

  async send(frame: Uint8Array): Promise<void> {
    if (this.closed) throw new Error('photonic carrier is closed');
    if (frame.length > PHOTONIC_FRAME_BYTES) {
      throw new Error(`photonic frame is ${frame.length} bytes, max ${PHOTONIC_FRAME_BYTES}`);
    }
    await this.link.display(frame, this.frameDurationMs);
  }

  /** Validate the next captured frame and dispatch it, or return null. */
  async receiveOnce(): Promise<Uint8Array | null> {
    if (this.closed) throw new Error('photonic carrier is closed');
    const captured = await this.link.capture();
    if (!captured) return null;
    const parsed = tryDecodeFrame(captured);
    if (!parsed) return null;
    const frame = captured.slice(0, parsed.frameBytes);
    for (const handler of [...this.handlers]) handler(frame);
    return frame;
  }

  onReceive(handler: (frame: Uint8Array) => void): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  async close(): Promise<void> {
    this.closed = true;
    this.handlers.clear();
    await this.link.close?.();
  }
}

/* ------------------------------------------------------------------ */
/* SMS carrier: Base85 text frames                                     */
/* ------------------------------------------------------------------ */

export interface SmsTransport {
  send(text: string): Promise<void> | void;
  onMessage(handler: (text: string) => void): () => void;
  close?(): Promise<void> | void;
}

export const SMS_TEXT_LIMIT = 140;
export const SMS_PREFIX = 'QP1:';
export const SMS_MAX_PAYLOAD_BYTES = 80;

export class SmsCarrier implements Carrier {
  readonly name = 'sms';
  readonly maxPayloadBytes: number;
  private handlers = new Set<(frame: Uint8Array) => void>();
  private readonly transport: SmsTransport;
  private readonly prefix: string;
  private unsubscribe: () => void;
  private closed = false;

  constructor(transport: SmsTransport, options: { prefix?: string; maxPayloadBytes?: number } = {}) {
    this.transport = transport;
    this.prefix = options.prefix ?? SMS_PREFIX;
    this.maxPayloadBytes = options.maxPayloadBytes ?? SMS_MAX_PAYLOAD_BYTES;
    this.unsubscribe = transport.onMessage((text) => this.handleText(text));
  }

  private handleText(text: string): void {
    if (this.closed || !text.startsWith(this.prefix)) return;
    try {
      const frame = base85Decode(text.slice(this.prefix.length), SMS_BASE85_ALPHABET);
      const parsed = tryDecodeFrame(frame);
      if (!parsed) return;
      for (const handler of [...this.handlers]) {
        handler(frame.slice(0, parsed.frameBytes));
      }
    } catch {
      // Malformed SMS: drop silently. The transport is untrusted.
    }
  }

  async send(frame: Uint8Array): Promise<void> {
    if (this.closed) throw new Error('SMS carrier is closed');
    const text = this.prefix + base85Encode(frame, SMS_BASE85_ALPHABET);
    if (text.length > SMS_TEXT_LIMIT) {
      throw new Error(`SMS frame is ${text.length} characters, limit ${SMS_TEXT_LIMIT}`);
    }
    await this.transport.send(text);
  }

  onReceive(handler: (frame: Uint8Array) => void): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  async close(): Promise<void> {
    this.closed = true;
    this.handlers.clear();
    this.unsubscribe();
    await this.transport.close?.();
  }
}

/** Two SMS endpoints wired together, for tests and local demos. */
export function createSmsLoopbackPair(): [SmsCarrier, SmsCarrier] {
  const handlersA = new Set<(text: string) => void>();
  const handlersB = new Set<(text: string) => void>();
  const transportA: SmsTransport = {
    send(text) {
      for (const handler of [...handlersB]) handler(text);
    },
    onMessage(handler) {
      handlersA.add(handler);
      return () => handlersA.delete(handler);
    },
  };
  const transportB: SmsTransport = {
    send(text) {
      for (const handler of [...handlersA]) handler(text);
    },
    onMessage(handler) {
      handlersB.add(handler);
      return () => handlersB.delete(handler);
    },
  };
  return [new SmsCarrier(transportA), new SmsCarrier(transportB)];
}

/* ------------------------------------------------------------------ */
/* Multipath transport                                                 */
/* ------------------------------------------------------------------ */

export interface MultipathMessage extends ReassembledMessage {
  /** Carrier that delivered the final fragment. */
  carrier: string;
}

export interface MultipathOptions {
  reassembler?: Reassembler;
  /** Carrier name to try first. */
  preferred?: string;
}

export interface SendMessageOptions {
  sessionId?: number;
  messageId?: number;
  flags?: number;
}

export class MultipathTransport {
  private carriers: Carrier[] = [];
  private readonly subscriptions: Array<() => void> = [];
  private readonly handlers = new Set<(message: MultipathMessage) => void>();
  private readonly reassembler: Reassembler;
  private preferred: string | null;
  private closed = false;
  readonly stats = {
    framesSent: 0,
    framesReceived: 0,
    sendFailures: 0,
    messagesSent: 0,
    messagesReceived: 0,
  };

  constructor(carriers: Carrier[] = [], options: MultipathOptions = {}) {
    this.reassembler = options.reassembler ?? new Reassembler();
    this.preferred = options.preferred ?? null;
    for (const carrier of carriers) this.addCarrier(carrier);
  }

  addCarrier(carrier: Carrier): void {
    if (this.closed) throw new Error('transport is closed');
    this.carriers.push(carrier);
    this.subscriptions.push(carrier.onReceive((frame) => this.ingest(carrier.name, frame)));
  }

  /** Replace a carrier by name (e.g. reconnecting an SMS link). */
  removeCarrier(name: string): void {
    this.carriers = this.carriers.filter((carrier) => carrier.name !== name);
    if (this.preferred === name) this.preferred = null;
  }

  setPreferred(name: string | null): void {
    this.preferred = name;
  }

  getCarriers(): ReadonlyArray<Carrier> {
    return this.carriers;
  }

  /** Smallest common payload size, so any frame can use any carrier. */
  commonPayloadBytes(): number {
    if (this.carriers.length === 0) throw new Error('no carriers configured');
    return Math.min(...this.carriers.map((carrier) => carrier.maxPayloadBytes));
  }

  private orderedCarriers(): Carrier[] {
    const available = this.carriers.filter((carrier) => carrier.available?.() !== false);
    if (!this.preferred) return available;
    const preferred = available.find((carrier) => carrier.name === this.preferred);
    if (!preferred) return available;
    return [preferred, ...available.filter((carrier) => carrier !== preferred)];
  }

  /** Send a single frame, failing over between carriers. */
  async sendFrame(frame: Uint8Array): Promise<string> {
    if (this.closed) throw new Error('transport is closed');
    const carriers = this.orderedCarriers();
    if (carriers.length === 0) throw new Error('no available carriers');
    let lastError: unknown = null;
    for (const carrier of carriers) {
      try {
        await carrier.send(frame);
        this.stats.framesSent++;
        return carrier.name;
      } catch (error) {
        this.stats.sendFailures++;
        lastError = error;
      }
    }
    throw lastError instanceof Error ? lastError : new Error('all carriers failed');
  }

  /**
   * Fragment and send a message. Fragments use the smallest common carrier
   * payload, so any fragment can fail over to any carrier.
   */
  async sendMessage(
    type: FrameType,
    payload: Uint8Array,
    options: SendMessageOptions = {}
  ): Promise<{ messageId: number; fragments: number; carriers: string[] }> {
    if (this.carriers.length === 0) throw new Error('no carriers configured');
    const messageId = (options.messageId ?? randomUint32()) >>> 0;
    const sessionId = (options.sessionId ?? 0) >>> 0;
    const frames = fragmentMessage(type, payload, {
      sessionId,
      messageId,
      maxPayloadBytes: this.commonPayloadBytes(),
      flags: options.flags ?? FrameFlags.None,
    });
    const used: string[] = [];
    for (const frame of frames) {
      used.push(await this.sendFrame(frame));
    }
    this.stats.messagesSent++;
    return { messageId, fragments: frames.length, carriers: used };
  }

  ingest(carrierName: string, frameBytes: Uint8Array): MultipathMessage | null {
    this.stats.framesReceived++;
    const message = this.reassembler.addBytes(frameBytes);
    if (!message) return null;
    this.stats.messagesReceived++;
    const enriched: MultipathMessage = { ...message, carrier: carrierName };
    for (const handler of [...this.handlers]) handler(enriched);
    return enriched;
  }

  onMessage(handler: (message: MultipathMessage) => void): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  reassemblerInstance(): Reassembler {
    return this.reassembler;
  }

  async close(): Promise<void> {
    this.closed = true;
    this.handlers.clear();
    for (const unsubscribe of this.subscriptions) unsubscribe();
    this.subscriptions.length = 0;
    await Promise.all(this.carriers.map((carrier) => carrier.close().catch(() => undefined)));
    this.carriers = [];
  }
}

function randomUint32(): number {
  const webCrypto = globalThis.crypto;
  if (webCrypto?.getRandomValues) {
    const buffer = new Uint32Array(1);
    webCrypto.getRandomValues(buffer);
    return buffer[0];
  }
  return Math.floor(Math.random() * 0x100000000) >>> 0;
}

/** Split a frame into carrier-sized pieces (used by informational APIs). */
export function frameWireSize(frameBytes: number): number {
  return frameBytes;
}

/** Join fragments that arrived as raw frame bytes. */
export function joinFrames(frames: Uint8Array[]): Uint8Array | null {
  const reassembler = new Reassembler();
  let result: ReassembledMessage | null = null;
  for (const frame of frames) {
    const message = reassembler.addBytes(frame);
    if (message) result = message;
  }
  return result ? result.payload : null;
}
