/**
 * End-to-end QuaNet session: ML-KEM handshake plus directional
 * ChaCha20-Poly1305 record encryption.
 *
 * Handshake:
 *
 *   initiator                                     responder
 *   ---------                                     ---------
 *   (pk, sk) <- ML-KEM keygen
 *   pk                ------------------------->
 *                                                 ct, ss <- Encapsulate(pk)
 *                                                 transcript = SHA3-256(pk || ct)
 *                     <-------------------------  ct || confirm(ss, transcript)
 *   ss <- Decapsulate(sk, ct)
 *   verify confirm(ss, transcript)
 *
 * Both ends derive independent initiator->responder and responder->initiator
 * keys with SHAKE256. Records use a 12-byte nonce (4-byte direction prefix +
 * 8-byte counter) and a 64-record replay window.
 *
 * CAVEAT: the handshake is unauthenticated by default. It protects against
 * passive quantum-capable adversaries, but an active man-in-the-middle can
 * substitute its own ML-KEM key. Applications that need peer identity should
 * pin an out-of-band fingerprint (see `fingerprintPublicKey`) or run an
 * authenticated protocol on top.
 */

import {
  MLKEM_CIPHERTEXT_BYTES,
  MLKEM_PUBLIC_KEY_BYTES,
  mlkemDecapsulate,
  mlkemEncapsulate,
  mlkemKeygen,
  type MlKemKeyPair,
} from '../crypto/mlkem.js';
import { sha3_256, shake256 } from '../crypto/keccak.js';
import { aeadOpenCombined, aeadSealCombined } from '../crypto/chacha20poly1305.js';
import { bytesEqual, concatBytes, fromHex, toHex } from '../util/bits.js';

export const SESSION_CONFIRM_BYTES = 16;
export const SESSION_RESPONSE_BYTES = MLKEM_CIPHERTEXT_BYTES + SESSION_CONFIRM_BYTES;
export const SESSION_NONCE_BYTES = 12;
export const SESSION_REPLAY_WINDOW = 64;

export type SessionRole = 'initiator' | 'responder';

export interface HandshakeOptions {
  /** Deterministic keygen seed (tests). */
  keygenSeed?: Uint8Array;
  /** Deterministic implicit-rejection seed (tests). */
  rejectionSeed?: Uint8Array;
  /** Deterministic encapsulation randomness (tests). */
  encapsulationRandomness?: Uint8Array;
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function derive(secret: Uint8Array, transcript: Uint8Array, label: string, length: number): Uint8Array {
  return shake256(concatBytes(secret, transcript, utf8(label)), length);
}

function confirmation(secret: Uint8Array, transcript: Uint8Array): Uint8Array {
  return derive(secret, transcript, 'responder-confirm', SESSION_CONFIRM_BYTES);
}

function u32Bytes(value: number): Uint8Array {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function bigintToBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function bytesToBigint(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

/** Stable identifier for a public key (pin this out of band if needed). */
export function fingerprintPublicKey(publicKey: Uint8Array): string {
  return toHex(sha3_256(publicKey));
}

/**
 * Encrypt/decrypt records for one direction-pair. Instances are created by
 * the handshake classes, not directly.
 */
export class QuaNetSession {
  readonly sessionId: number;
  readonly role: SessionRole;
  readonly transcriptHash: Uint8Array;
  private readonly sendKey: Uint8Array;
  private readonly receiveKey: Uint8Array;
  private readonly sendPrefix: Uint8Array;
  private readonly receivePrefix: Uint8Array;
  private sendCounter = 0n;
  private highestReceive = -1n;
  private replayWindow = 0n;
  private recordsSent = 0;
  private recordsReceived = 0;

  constructor(init: {
    sessionId: number;
    role: SessionRole;
    transcriptHash: Uint8Array;
    sendKey: Uint8Array;
    receiveKey: Uint8Array;
    sendPrefix: Uint8Array;
    receivePrefix: Uint8Array;
  }) {
    this.sessionId = init.sessionId;
    this.role = init.role;
    this.transcriptHash = init.transcriptHash;
    this.sendKey = init.sendKey;
    this.receiveKey = init.receiveKey;
    this.sendPrefix = init.sendPrefix;
    this.receivePrefix = init.receivePrefix;
  }

  /** Next nonce, exported for test vectors. */
  nextNonce(): Uint8Array {
    const nonce = new Uint8Array(SESSION_NONCE_BYTES);
    nonce.set(this.sendPrefix, 0);
    nonce.set(bigintToBytes(this.sendCounter, 8), 4);
    return nonce;
  }

  /**
   * Encrypt a record. Returns nonce || ciphertext || tag. The nonce is
   * included so carriers do not need to preserve record ordering.
   */
  encrypt(plaintext: Uint8Array, aad: Uint8Array = new Uint8Array(0)): Uint8Array {
    const nonce = this.nextNonce();
    const combined = aeadSealCombined(this.sendKey, nonce, plaintext, this.buildAad(aad));
    this.sendCounter++;
    this.recordsSent++;
    return concatBytes(nonce, combined);
  }

  encryptText(text: string, aad: Uint8Array = new Uint8Array(0)): Uint8Array {
    return this.encrypt(utf8(text), aad);
  }

  /**
   * Verify and decrypt a record. Enforces a 64-record replay window. Throws on
   * authentication failure, malformed input or replay.
   */
  decrypt(record: Uint8Array, aad: Uint8Array = new Uint8Array(0)): Uint8Array {
    if (record.length < SESSION_NONCE_BYTES + 16) throw new Error('record too short');
    const nonce = record.subarray(0, SESSION_NONCE_BYTES);
    const prefix = nonce.subarray(0, 4);
    if (!bytesEqual(prefix, this.receivePrefix)) {
      throw new Error('record nonce belongs to a different direction');
    }
    const counter = bytesToBigint(nonce.subarray(4));
    this.checkReplay(counter);

    const plaintext = aeadOpenCombined(
      this.receiveKey,
      nonce,
      record.subarray(SESSION_NONCE_BYTES),
      this.buildAad(aad)
    );
    this.markReceived(counter);
    this.recordsReceived++;
    return plaintext;
  }

  decryptText(record: Uint8Array, aad: Uint8Array = new Uint8Array(0)): string {
    return new TextDecoder().decode(this.decrypt(record, aad));
  }

  stats(): { recordsSent: number; recordsReceived: number; sendCounter: string } {
    return {
      recordsSent: this.recordsSent,
      recordsReceived: this.recordsReceived,
      sendCounter: this.sendCounter.toString(),
    };
  }

  private buildAad(extra: Uint8Array): Uint8Array {
    return concatBytes(u32Bytes(this.sessionId), extra);
  }

  private checkReplay(counter: bigint): void {
    if (counter > this.highestReceive) return;
    const distance = this.highestReceive - counter;
    if (distance >= BigInt(SESSION_REPLAY_WINDOW)) {
      throw new Error('record is outside the replay window');
    }
    const bit = 1n << distance;
    if ((this.replayWindow & bit) !== 0n) throw new Error('replayed record');
  }

  private markReceived(counter: bigint): void {
    if (counter > this.highestReceive) {
      const shift = counter - this.highestReceive;
      this.replayWindow =
        shift >= BigInt(SESSION_REPLAY_WINDOW)
          ? 0n
          : (this.replayWindow << shift) & ((1n << BigInt(SESSION_REPLAY_WINDOW)) - 1n);
      this.replayWindow |= 1n;
      this.highestReceive = counter;
    } else {
      const distance = this.highestReceive - counter;
      this.replayWindow |= 1n << distance;
    }
  }
}

function buildSession(
  role: SessionRole,
  secret: Uint8Array,
  transcript: Uint8Array
): QuaNetSession {
  const sessionId = Number(bytesToBigint(transcript.subarray(0, 4))) >>> 0;
  const initiatorToResponder = derive(secret, transcript, 'key-i2r', 32);
  const responderToInitiator = derive(secret, transcript, 'key-r2i', 32);
  const nonceI2R = derive(secret, transcript, 'nonce-i2r', 4);
  const nonceR2I = derive(secret, transcript, 'nonce-r2i', 4);
  const initiator = role === 'initiator';
  return new QuaNetSession({
    sessionId,
    role,
    transcriptHash: transcript,
    sendKey: initiator ? initiatorToResponder : responderToInitiator,
    receiveKey: initiator ? responderToInitiator : initiatorToResponder,
    sendPrefix: initiator ? nonceI2R : nonceR2I,
    receivePrefix: initiator ? nonceR2I : nonceI2R,
  });
}

/** Initiator side of the handshake. */
export class InitiatorHandshake {
  readonly publicKey: Uint8Array;
  private readonly keyPair: MlKemKeyPair;
  private completed = false;

  private constructor(keyPair: MlKemKeyPair) {
    this.keyPair = keyPair;
    this.publicKey = keyPair.publicKey;
  }

  static create(options: HandshakeOptions = {}): InitiatorHandshake {
    return new InitiatorHandshake(mlkemKeygen(options.keygenSeed, options.rejectionSeed));
  }

  /** Handshake message to send to the responder (1184 bytes). */
  message(): Uint8Array {
    return this.publicKey;
  }

  /** Process the responder's response and return the live session. */
  complete(response: Uint8Array): QuaNetSession {
    if (this.completed) throw new Error('handshake already completed');
    if (response.length !== SESSION_RESPONSE_BYTES) {
      throw new Error(`handshake response must be ${SESSION_RESPONSE_BYTES} bytes`);
    }
    const ciphertext = response.subarray(0, MLKEM_CIPHERTEXT_BYTES);
    const receivedConfirm = response.subarray(MLKEM_CIPHERTEXT_BYTES);
    const secret = mlkemDecapsulate(this.keyPair.secretKey, ciphertext);
    const transcript = sha3_256(concatBytes(this.publicKey, ciphertext));
    if (!bytesEqual(confirmation(secret, transcript), receivedConfirm)) {
      throw new Error('handshake confirmation failed');
    }
    this.completed = true;
    return buildSession('initiator', secret, transcript);
  }
}

/** Responder side of the handshake. */
export class ResponderHandshake {
  readonly session: QuaNetSession;
  readonly response: Uint8Array;

  private constructor(session: QuaNetSession, response: Uint8Array) {
    this.session = session;
    this.response = response;
  }

  static accept(initMessage: Uint8Array, options: HandshakeOptions = {}): ResponderHandshake {
    if (initMessage.length !== MLKEM_PUBLIC_KEY_BYTES) {
      throw new Error(`handshake init must be ${MLKEM_PUBLIC_KEY_BYTES} bytes`);
    }
    const { ciphertext, sharedSecret } = mlkemEncapsulate(
      initMessage,
      options.encapsulationRandomness
    );
    const transcript = sha3_256(concatBytes(initMessage, ciphertext));
    const response = concatBytes(
      ciphertext,
      confirmation(sharedSecret, transcript)
    );
    const session = buildSession('responder', sharedSecret, transcript);
    return new ResponderHandshake(session, response);
  }
}

/** Convenience: run the whole handshake locally (tests, simulations). */
export function establishLocalSession(options: HandshakeOptions = {}): {
  initiator: QuaNetSession;
  responder: QuaNetSession;
} {
  const initiatorHandshake = InitiatorHandshake.create(options);
  const responderHandshake = ResponderHandshake.accept(initiatorHandshake.message(), options);
  const initiator = initiatorHandshake.complete(responderHandshake.response);
  return { initiator, responder: responderHandshake.session };
}

/** Hex helpers for session identifiers. */
export function sessionIdHex(session: QuaNetSession): string {
  return toHex(u32Bytes(session.sessionId));
}

export function sessionIdFromHex(hex: string): number {
  const bytes = fromHex(hex);
  if (bytes.length !== 4) throw new Error('session id must be four bytes');
  return Number(bytesToBigint(bytes));
}
