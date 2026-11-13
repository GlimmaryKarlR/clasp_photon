import test from 'node:test';
import assert from 'node:assert/strict';

import {
  base85Encode,
  base85Decode,
  base85DecodeExact,
  ASCII85_ALPHABET,
  SMS_BASE85_ALPHABET,
} from '../dist/transport/base85.js';
import {
  FrameType,
  FrameFlags,
  FRAME_MAGIC,
  FRAME_HEADER_BYTES,
  FRAME_OVERHEAD_BYTES,
  crc32,
  encodeFrame,
  decodeFrame,
  tryDecodeFrame,
  buildFrame,
  fragmentMessage,
  Reassembler,
  reassembleFrames,
} from '../dist/transport/framing.js';
import {
  LoopbackCarrier,
  createLoopbackPair,
  PhotonicCarrier,
  createSmsLoopbackPair,
  MultipathTransport,
  SMS_TEXT_LIMIT,
  PHOTONIC_FRAME_BYTES,
} from '../dist/transport/carriers.js';

function payload(length, seed = 1) {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) bytes[i] = (i * 31 + seed * 7) & 0xff;
  return bytes;
}

test('Base85 round-trips arbitrary byte lengths with both alphabets', () => {
  for (const alphabet of [ASCII85_ALPHABET, SMS_BASE85_ALPHABET]) {
    for (let length = 0; length <= 21; length++) {
      const bytes = payload(length, length);
      const encoded = base85Encode(bytes, alphabet);
      const decoded = base85DecodeExact(encoded, length, alphabet);
      assert.deepEqual(Array.from(decoded), Array.from(bytes), `length ${length}`);
    }
  }
  assert.equal(base85Encode(new Uint8Array(4), ASCII85_ALPHABET), '!!!!!');
  assert.throws(() => base85Decode('a', ASCII85_ALPHABET), /too short/);
  assert.throws(() => base85Decode('!', ASCII85_ALPHABET), /too short/);
});

test('CRC-32 matches the IEEE check value', () => {
  assert.equal(crc32(new TextEncoder().encode('123456789')), 0xcbf43926);
  assert.equal(crc32(new Uint8Array(0)), 0);
});

test('frames encode and decode with a validated header and CRC', () => {
  const body = payload(32, 3);
  const encoded = buildFrame(FrameType.Data, body, {
    sessionId: 0x11223344,
    messageId: 0xaabbccdd,
    fragmentIndex: 2,
    fragmentCount: 5,
    flags: FrameFlags.NeedsAck,
  });

  assert.equal(encoded.length, FRAME_OVERHEAD_BYTES + body.length);
  assert.equal(encoded[0], FRAME_MAGIC[0]);
  assert.equal(encoded[1], FRAME_MAGIC[1]);
  assert.equal(encoded[2], 1);

  const decoded = decodeFrame(encoded);
  assert.equal(decoded.type, FrameType.Data);
  assert.equal(decoded.sessionId, 0x11223344);
  assert.equal(decoded.messageId, 0xaabbccdd);
  assert.equal(decoded.fragmentIndex, 2);
  assert.equal(decoded.fragmentCount, 5);
  assert.equal(decoded.flags, FrameFlags.NeedsAck);
  assert.deepEqual(Array.from(decoded.payload), Array.from(body));
  assert.equal(decoded.frameBytes, encoded.length);
});

test('frame parser rejects corruption, truncation and trailing padding is ignored', () => {
  const encoded = buildFrame(FrameType.Data, payload(16, 2), { sessionId: 7 });
  const tampered = encoded.slice();
  tampered[FRAME_HEADER_BYTES] ^= 0x10;
  assert.throws(() => decodeFrame(tampered), /CRC/);
  assert.equal(tryDecodeFrame(tampered), null);

  assert.throws(() => decodeFrame(encoded.subarray(0, encoded.length - 2)), /truncated/);
  const badMagic = encoded.slice();
  badMagic[0] = 0;
  assert.throws(() => decodeFrame(badMagic), /magic/);
  assert.throws(() => decodeFrame(new Uint8Array(4)), /too short/);

  // Padding after the CRC (for example optical block padding) is allowed.
  const padded = new Uint8Array(encoded.length + 32);
  padded.set(encoded);
  const parsed = decodeFrame(padded);
  assert.equal(parsed.frameBytes, encoded.length);
});

test('fragmentMessage splits with Last flags and reassembles out of order', () => {
  const message = payload(500, 5);
  const frames = fragmentMessage(FrameType.Data, message, {
    sessionId: 9,
    messageId: 77,
    maxPayloadBytes: 100,
  });
  assert.equal(frames.length, 5);
  assert.ok(frames.slice(0, 4).every((frame) => (decodeFrame(frame).flags & FrameFlags.Last) === 0));
  assert.ok(decodeFrame(frames[4]).flags & FrameFlags.Last);

  const reassembler = new Reassembler();
  // The duplicate of fragment 2 arrives before fragment 0 completes the
  // message. A duplicate after completion starts a fresh pending bucket by
  // design, so it must precede the final fragment here.
  const order = [3, 1, 4, 2, 2, 0];
  let result = null;
  for (const index of order) {
    const messageResult = reassembler.addBytes(frames[index]);
    if (messageResult) result = messageResult;
  }
  assert.ok(result);
  assert.equal(result.sessionId, 9);
  assert.equal(result.messageId, 77);
  assert.equal(result.fragments, 5);
  assert.deepEqual(Array.from(result.payload), Array.from(message));
  assert.equal(reassembler.pendingCount(), 0);

  // One-shot helper produces the same bytes.
  assert.deepEqual(
    Array.from(reassembleFrames(frames.map((frame) => decodeFrame(frame))).payload),
    Array.from(message)
  );
});

test('Reassembler rejects conflicting metadata and expires stale messages', () => {
  const reassembler = new Reassembler({ timeoutMs: 1000 });
  const first = decodeFrame(
    buildFrame(FrameType.Data, payload(10, 1), {
      sessionId: 1,
      messageId: 2,
      fragmentIndex: 0,
      fragmentCount: 2,
    })
  );
  assert.equal(reassembler.add(first, 0), null);
  assert.equal(reassembler.pendingCount(), 1);

  // Same bucket, conflicting fragment count.
  const conflicting = decodeFrame(
    buildFrame(FrameType.Data, payload(10, 1), {
      sessionId: 1,
      messageId: 2,
      fragmentIndex: 1,
      fragmentCount: 3,
    })
  );
  assert.equal(reassembler.add(conflicting, 10), null);
  assert.equal(reassembler.pendingCount(), 1);

  assert.equal(reassembler.expire(2000), 1);
  assert.equal(reassembler.pendingCount(), 0);
});

test('SMS loopback carries validated frames as text', async () => {
  const [a, b] = createSmsLoopbackPair();
  const received = [];
  b.onReceive((frame) => received.push(frame));

  const frame = buildFrame(FrameType.Data, payload(30, 4), {
    sessionId: 3,
    messageId: 4,
  });
  await a.send(frame);
  assert.equal(received.length, 1);
  assert.deepEqual(Array.from(received[0]), Array.from(frame));

  // Oversized SMS frames are rejected before hitting the transport.
  const large = buildFrame(FrameType.Data, payload(200, 4));
  await assert.rejects(() => a.send(large), /SMS frame/);

  await a.close();
  await b.close();
});

test('Photonic carrier moves opaque frames over a display/capture link', async () => {
  const shown = [];
  const tx = new PhotonicCarrier({
    link: {
      display(frame) {
        shown.push(frame);
      },
      capture() {
        throw new Error('transmitter cannot capture');
      },
    },
  });
  const rx = new PhotonicCarrier({
    link: {
      display() {},
      capture() {
        return shown.shift() ?? null;
      },
    },
  });

  const frame = buildFrame(FrameType.Data, payload(40, 6), {
    sessionId: 11,
    messageId: 22,
  });
  assert.ok(frame.length <= PHOTONIC_FRAME_BYTES);
  await tx.send(frame);
  assert.equal(shown.length, 1);
  // The carrier does not render or interpret an image; it forwards frame bytes.
  assert.deepEqual(Array.from(shown[0]), Array.from(frame));

  const received = [];
  rx.onReceive((bytes) => received.push(bytes));
  const decoded = await rx.receiveOnce();
  assert.ok(decoded);
  assert.deepEqual(Array.from(decoded), Array.from(frame));
  assert.deepEqual(Array.from(received[0]), Array.from(frame));

  // Random or malformed captures must not decode to a frame.
  shown.push(new Uint8Array(32).fill(0xa5));
  assert.equal(await rx.receiveOnce(), null);

  await tx.close();
  await rx.close();
});

test('MultipathTransport fragments, fails over and reassembles', async () => {
  const [wireA, wireB] = createLoopbackPair();
  let flakyAttempts = 0;
  const flaky = {
    name: 'flaky',
    maxPayloadBytes: 400,
    async send() {
      flakyAttempts++;
      throw new Error('carrier offline');
    },
    onReceive() {
      return () => {};
    },
    async close() {},
    available() {
      return true;
    },
  };

  const sender = new MultipathTransport([flaky, wireA]);
  const receiver = new MultipathTransport([wireB]);

  assert.equal(sender.commonPayloadBytes(), Math.min(400, wireA.maxPayloadBytes));

  const messages = [];
  receiver.onMessage((message) => messages.push(message));

  const body = payload(420, 8);
  const info = await sender.sendMessage(FrameType.Data, body, {
    sessionId: 5,
    messageId: 6,
  });
  assert.ok(info.fragments > 1);
  assert.ok(info.carriers.every((name) => name === 'loopback-a'));
  assert.ok(flakyAttempts >= info.fragments);

  assert.equal(messages.length, 1);
  assert.equal(messages[0].sessionId, 5);
  assert.equal(messages[0].messageId, 6);
  assert.equal(messages[0].carrier, 'loopback-b');
  assert.deepEqual(Array.from(messages[0].payload), Array.from(body));

  assert.equal(sender.stats.framesSent, info.fragments);
  assert.ok(sender.stats.sendFailures >= info.fragments);
  assert.equal(receiver.stats.messagesReceived, 1);

  await sender.close();
  await receiver.close();
});

test('MultipathTransport honours carrier availability and preferred order', async () => {
  const [wireA, wireB] = createLoopbackPair();
  let used = [];
  const recorder = new LoopbackCarrier('preferred', {});
  recorder.peer = {
    deliver(frame) {
      used.push('preferred');
      wireB.deliver(frame);
    },
  };
  // Replace recorder's delivery to also forward to the receiving transport.
  wireA.peer = null;

  const sender = new MultipathTransport([wireA]);
  sender.addCarrier(recorder);
  sender.setPreferred('preferred');
  const receiver = new MultipathTransport([wireB]);

  const messages = [];
  receiver.onMessage((message) => messages.push(message));

  await sender.sendMessage(FrameType.Data, payload(40, 9), { sessionId: 1, messageId: 2 });
  assert.ok(used.length >= 1);
  assert.equal(messages.length, 1);

  await sender.close();
  await receiver.close();
});

test('LoopbackCarrier can drop and corrupt frames deterministically', async () => {
  const [a, b] = createLoopbackPair({ dropRate: 1, seed: 5 });
  const received = [];
  b.onReceive((frame) => received.push(frame));
  await a.send(buildFrame(FrameType.Data, payload(8, 1)));
  assert.equal(received.length, 0);

  const [c, d] = createLoopbackPair({ corruptRate: 1, seed: 9 });
  const corrupted = [];
  d.onReceive((frame) => corrupted.push(frame));
  const frame = buildFrame(FrameType.Data, payload(8, 1));
  await c.send(frame);
  assert.equal(corrupted.length, 1);
  assert.notDeepEqual(Array.from(corrupted[0]), Array.from(frame));

  await a.close();
  await b.close();
  await c.close();
  await d.close();
});

test('SMS text limit is respected', () => {
  assert.equal(SMS_TEXT_LIMIT, 140);
});
