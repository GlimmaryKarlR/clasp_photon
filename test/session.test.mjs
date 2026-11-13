import test from 'node:test';
import assert from 'node:assert/strict';

import {
  InitiatorHandshake,
  ResponderHandshake,
  establishLocalSession,
  fingerprintPublicKey,
  sessionIdHex,
  sessionIdFromHex,
  SESSION_REPLAY_WINDOW,
  SESSION_RESPONSE_BYTES,
} from '../dist/session/quanetSession.js';
import {
  MLKEM_PUBLIC_KEY_BYTES,
  MLKEM_CIPHERTEXT_BYTES,
} from '../dist/crypto/mlkem.js';
import {
  FrameType,
  buildFrame,
  decodeFrame,
} from '../dist/transport/framing.js';
import {
  createSmsLoopbackPair,
  PhotonicCarrier,
  MultipathTransport,
} from '../dist/transport/carriers.js';
import { bytesEqual, toHex } from '../dist/util/bits.js';

const deterministic = {
  keygenSeed: new Uint8Array(32).fill(0x11),
  rejectionSeed: new Uint8Array(32).fill(0x22),
  encapsulationRandomness: new Uint8Array(32).fill(0x33),
};

test('handshake establishes matching session state on both ends', () => {
  const { initiator, responder } = establishLocalSession(deterministic);

  assert.equal(initiator.role, 'initiator');
  assert.equal(responder.role, 'responder');
  assert.equal(initiator.sessionId, responder.sessionId);
  assert.deepEqual(
    Array.from(initiator.transcriptHash),
    Array.from(responder.transcriptHash)
  );
  assert.equal(sessionIdFromHex(sessionIdHex(initiator)), initiator.sessionId);

  assert.equal(initiator.stats().sendCounter, '0');
  assert.equal(responder.stats().sendCounter, '0');
});

test('handshake wire sizes and response layout are stable', () => {
  const initiator = InitiatorHandshake.create(deterministic);
  assert.equal(initiator.message().length, MLKEM_PUBLIC_KEY_BYTES);

  const responder = ResponderHandshake.accept(initiator.message(), deterministic);
  assert.equal(responder.response.length, SESSION_RESPONSE_BYTES);
  assert.equal(
    SESSION_RESPONSE_BYTES,
    MLKEM_CIPHERTEXT_BYTES + 16
  );
  assert.equal(fingerprintPublicKey(initiator.message()).length, 64);
});

test('both directions encrypt and decrypt with associated data', () => {
  const { initiator, responder } = establishLocalSession(deterministic);
  const aad = new TextEncoder().encode('channel=sms');

  const fromInitiator = initiator.encryptText('hello responder', aad);
  assert.equal(responder.decryptText(fromInitiator, aad), 'hello responder');

  const fromResponder = responder.encryptText('hello initiator', aad);
  assert.equal(initiator.decryptText(fromResponder, aad), 'hello initiator');

  // Directional keys and nonce prefixes mean the streams are independent.
  assert.ok(!bytesEqual(fromInitiator.subarray(0, 4), fromResponder.subarray(0, 4)));
  assert.equal(initiator.stats().recordsSent, 1);
  assert.equal(responder.stats().recordsReceived, 1);
  assert.equal(responder.stats().recordsSent, 1);
  assert.equal(initiator.stats().recordsReceived, 1);
});

test('tampered records, wrong AAD and wrong direction are rejected', () => {
  const { initiator, responder } = establishLocalSession(deterministic);
  const record = initiator.encryptText('authentic');

  const tampered = record.slice();
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => responder.decrypt(tampered), /authentication|tag|failed/i);

  const wrongAad = new TextEncoder().encode('other');
  const fresh = initiator.encryptText('authentic');
  assert.throws(() => responder.decrypt(fresh, wrongAad), /authentication|tag|failed/i);

  // The responder's own outbound record uses the reverse prefix and must not
  // be accepted back on the responder side.
  const reversed = responder.encryptText('not yours');
  assert.throws(() => responder.decrypt(reversed), /direction/);

  assert.throws(() => responder.decrypt(new Uint8Array(8)), /too short/);
});

test('replayed records are rejected within the window', () => {
  const { initiator, responder } = establishLocalSession(deterministic);
  const first = initiator.encryptText('one');
  const second = initiator.encryptText('two');

  assert.equal(responder.decryptText(first), 'one');
  assert.throws(() => responder.decrypt(first), /replayed/);

  // The next record still works after a replay attempt.
  assert.equal(responder.decryptText(second), 'two');
});

test('64-record replay window accepts late records but rejects old ones', () => {
  const { initiator, responder } = establishLocalSession(deterministic);
  const records = [];
  for (let i = 0; i < SESSION_REPLAY_WINDOW; i++) {
    records.push(initiator.encryptText(`record ${i}`));
  }

  // Deliver the newest first, then everything else inside the window.
  assert.equal(responder.decryptText(records[records.length - 1]), 'record 63');
  for (let i = records.length - 2; i >= 0; i--) {
    assert.equal(responder.decryptText(records[i]), `record ${i}`);
  }

  // A duplicate inside the window is still a replay.
  assert.throws(() => responder.decrypt(records[0]), /replayed/);

  // Skip 64 records forward: anything at least 64 behind is outside the window.
  const far = [];
  for (let i = 0; i < SESSION_REPLAY_WINDOW + 1; i++) {
    far.push(initiator.encryptText(`far ${i}`));
  }
  assert.equal(responder.decryptText(far[far.length - 1]), `far 64`);
  assert.throws(() => responder.decrypt(far[0]), /outside the replay window/);
});

test('handshake rejects malformed input and bad confirmations', () => {
  assert.throws(() => InitiatorHandshake.create(deterministic).complete(new Uint8Array(4)), /1184|bytes/);
  assert.throws(() => ResponderHandshake.accept(new Uint8Array(12), deterministic), /1184|bytes/);

  const initiator = InitiatorHandshake.create(deterministic);
  const responder = ResponderHandshake.accept(initiator.message(), deterministic);
  const corrupted = responder.response.slice();
  corrupted[corrupted.length - 1] ^= 1;
  assert.throws(() => initiator.complete(corrupted), /confirmation/);
  // A failed handshake can be retried with the correct response.
  assert.ok(initiator.complete(responder.response));

  const used = InitiatorHandshake.create(deterministic);
  const response = ResponderHandshake.accept(used.message(), deterministic).response;
  used.complete(response);
  assert.throws(() => used.complete(response), /already completed/);
});

test('deterministic handshake seeds yield stable public keys and transcripts', () => {
  const a = establishLocalSession(deterministic);
  const b = establishLocalSession(deterministic);
  assert.equal(a.initiator.sessionId, b.initiator.sessionId);
  assert.equal(
    toHex(a.initiator.transcriptHash),
    toHex(b.initiator.transcriptHash)
  );

  const different = establishLocalSession({
    ...deterministic,
    keygenSeed: new Uint8Array(32).fill(0x44),
  });
  assert.notEqual(
    toHex(a.initiator.transcriptHash),
    toHex(different.initiator.transcriptHash)
  );
});

test('encrypted session runs end to end over the SMS carrier', async () => {
  const { initiator, responder } = establishLocalSession(deterministic);
  const [tx, rx] = createSmsLoopbackPair();

  const received = [];
  rx.onReceive((frame) => received.push(frame));

  const message = 'QuaNet over SMS';
  const record = initiator.encryptText(message);
  const frame = buildFrame(FrameType.Data, record, {
    sessionId: initiator.sessionId,
    messageId: 0x1234,
  });
  await tx.send(frame);

  assert.equal(received.length, 1);
  const decoded = decodeFrame(received[0]);
  assert.equal(decoded.sessionId, initiator.sessionId);
  assert.equal(responder.decryptText(decoded.payload), message);

  await tx.close();
  await rx.close();
});

test('encrypted session fragments across carriers and reassembles', async () => {
  const { initiator, responder } = establishLocalSession(deterministic);
  // A real SMS link only carries 80 payload bytes per frame after Base85 and
  // the QP1: prefix, so a long record exercises fragmentation and reassembly.
  const [smsA, smsB] = createSmsLoopbackPair();

  const sender = new MultipathTransport([smsA]);
  const receiver = new MultipathTransport([smsB]);
  const messages = [];
  receiver.onMessage((message) => messages.push(message));

  const plaintext = 'x'.repeat(400);
  const record = initiator.encryptText(plaintext);
  const info = await sender.sendMessage(FrameType.Data, record, {
    sessionId: initiator.sessionId,
    messageId: 0x5678,
  });
  assert.ok(info.fragments > 1);
  assert.deepEqual(info.carriers, Array(info.fragments).fill('sms'));
  assert.equal(messages.length, 1);
  assert.equal(messages[0].sessionId, initiator.sessionId);
  assert.equal(messages[0].carrier, 'sms');
  assert.equal(responder.decryptText(messages[0].payload), plaintext);

  await sender.close();
  await receiver.close();
});

test('full handshake and encrypted data run over SMS fragments', async () => {
  const [smsA, smsB] = createSmsLoopbackPair();
  const initiatorSide = new MultipathTransport([smsA]);
  const responderSide = new MultipathTransport([smsB]);

  // The 1184-byte ML-KEM public key is larger than one SMS frame, so the
  // handshake itself exercises fragmentation and reassembly.
  let responderSession = null;
  responderSide.onMessage(async (message) => {
    if (message.type !== FrameType.HandshakeInit) return;
    const handshake = ResponderHandshake.accept(message.payload, deterministic);
    responderSession = handshake.session;
    await responderSide.sendMessage(
      FrameType.HandshakeResponse,
      handshake.response,
      { sessionId: handshake.session.sessionId, messageId: 2 }
    );
  });

  const responsePromise = new Promise((resolve) => {
    initiatorSide.onMessage((message) => {
      if (message.type === FrameType.HandshakeResponse) resolve(message);
    });
  });

  const initiator = InitiatorHandshake.create(deterministic);
  const initInfo = await initiatorSide.sendMessage(
    FrameType.HandshakeInit,
    initiator.message(),
    { messageId: 1 }
  );
  assert.ok(initInfo.fragments > 1);

  const response = await responsePromise;
  const session = initiator.complete(response.payload);
  assert.ok(responderSession);
  assert.equal(session.sessionId, responderSession.sessionId);

  // Data records now flow through the same fragmented SMS path.
  const dataPromise = new Promise((resolve) => {
    responderSide.onMessage((message) => {
      if (message.type === FrameType.Data) resolve(message);
    });
  });
  const record = session.encryptText('handshake completed over SMS');
  await initiatorSide.sendMessage(FrameType.Data, record, {
    sessionId: session.sessionId,
    messageId: 3,
  });
  const data = await dataPromise;
  assert.equal(
    responderSession.decryptText(data.payload),
    'handshake completed over SMS'
  );

  await initiatorSide.close();
  await responderSide.close();
});

test('encrypted session renders over the photonic carrier', async () => {
  const { initiator, responder } = establishLocalSession(deterministic);
  const shown = [];
  const tx = new PhotonicCarrier({
    link: { display: (image) => shown.push(image), capture: () => null },
    maxIterations: 10,
  });
  const rx = new PhotonicCarrier({
    link: { display() {}, capture: () => shown.shift() ?? null },
    maxIterations: 10,
  });

  const record = initiator.encryptText('optical record');
  const frame = buildFrame(FrameType.Data, record, {
    sessionId: initiator.sessionId,
    messageId: 1,
  });
  await tx.send(frame);
  const received = await rx.receiveOnce();
  assert.ok(received);
  assert.equal(responder.decryptText(decodeFrame(received).payload), 'optical record');

  await tx.close();
  await rx.close();
});
