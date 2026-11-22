/**
 * QuaNet message envelopes — addressing without URLs.
 *
 * A channel is a content-derived identifier. Each message is named by the hash
 * of its own quanta and carries the XNOR signature produced against the
 * previous message, forming a verifiable chain. Fragmentation mirrors the
 * baseline frame in src/transport/framing.ts: message id and position travel
 * with every fragment so a message can fail over between carriers.
 */

import { sha256Hex } from '../photonicQuantumAnalyzer.js';
import {
  encodeQuanta,
  decodeQuanta,
  quantaFingerprint,
  resolveXnorFabric,
  type Quanta,
} from './quanta.js';

export const MESSAGE_SCHEMA = 'quanet.message.v1';

function digest(text: string): string {
  return sha256Hex(new TextEncoder().encode(text));
}

export function channelId(label: string, owner = 'local'): string {
  return `qn:${digest(`${owner}:${label}`).slice(0, 32)}`;
}

export interface QnEnvelope {
  schema: typeof MESSAGE_SCHEMA;
  id: string;
  channel: string;
  seq: number;
  createdAt: number;
  byteLength: number;
  quanta: Quanta[];
  fabric: string;
  dsl: boolean;
  ttl?: number;
}

export interface QnFragment {
  messageId: string;
  channel: string;
  seq: number;
  createdAt: number;
  index: number;
  count: number;
  byteLength: number;
  quanta: Quanta[];
  fabric: string;
  dsl: boolean;
}

export function createMessage(
  channel: string,
  seq: number,
  body: string | Uint8Array,
  previous?: QnEnvelope,
  dsl = false,
  ttl?: number
): QnEnvelope {
  const bytes = typeof body === 'string' ? new TextEncoder().encode(body) : body;
  const quanta = encodeQuanta(bytes);
  const fingerprint = quantaFingerprint(quanta);
  const fabric = previous ? resolveXnorFabric(previous.quanta, quanta).signature : fingerprint;
  const envelope: QnEnvelope = {
    schema: MESSAGE_SCHEMA,
    id: digest(`${channel}:${seq}:${fingerprint}`).slice(0, 32),
    channel,
    seq,
    createdAt: Date.now(),
    byteLength: bytes.length,
    quanta,
    fabric,
    dsl,
  };
  if (ttl !== undefined) envelope.ttl = ttl;
  return envelope;
}

export function readMessage(envelope: QnEnvelope): string {
  return new TextDecoder().decode(decodeQuanta(envelope.quanta, envelope.byteLength));
}

export function chainValid(previous: QnEnvelope, next: QnEnvelope): boolean {
  return resolveXnorFabric(previous.quanta, next.quanta).signature === next.fabric;
}

export function fragmentMessage(envelope: QnEnvelope, maxQuanta = 16): QnFragment[] {
  const total = Math.max(1, Math.ceil(envelope.quanta.length / maxQuanta));
  const fragments: QnFragment[] = [];
  for (let index = 0; index < total; index++) {
    fragments.push({
      messageId: envelope.id,
      channel: envelope.channel,
      seq: envelope.seq,
      createdAt: envelope.createdAt,
      index,
      count: total,
      byteLength: envelope.byteLength,
      quanta: envelope.quanta.slice(index * maxQuanta, (index + 1) * maxQuanta),
      fabric: envelope.fabric,
      dsl: envelope.dsl,
    });
  }
  return fragments;
}

export function reassembleMessage(fragments: QnFragment[]): QnEnvelope | null {
  if (fragments.length === 0) return null;
  const ordered = [...fragments].sort((a, b) => a.index - b.index);
  const count = ordered[0].count;
  if (ordered.length !== count) return null;
  for (let i = 0; i < count; i++) if (ordered[i].index !== i) return null;
  const head = ordered[0];
  return {
    schema: MESSAGE_SCHEMA,
    id: head.messageId,
    channel: head.channel,
    seq: head.seq,
    createdAt: head.createdAt,
    byteLength: head.byteLength,
    quanta: ordered.flatMap((fragment) => fragment.quanta),
    fabric: head.fabric,
    dsl: head.dsl,
  };
}
