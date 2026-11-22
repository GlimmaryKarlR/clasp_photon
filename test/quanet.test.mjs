import test from 'node:test';
import assert from 'node:assert/strict';

import {
  QUANTA_STATE_COUNT,
  collapse,
  decodeQuanta,
  encodeQuanta,
  quantaState,
  resolveXnorFabric,
  stateToQuanta,
  channelId,
  chainValid,
  createMessage,
  fragmentMessage,
  readMessage,
  reassembleMessage,
} from '../dist/quanet/index.js';

test('quanta exposes six distinct spin/qubit states', () => {
  const states = Array.from({ length: QUANTA_STATE_COUNT }, (_, i) =>
    quantaState(stateToQuanta(i))
  );
  assert.deepEqual(states, [0, 1, 2, 3, 4, 5]);
});

test('quanta round-trips byte streams', () => {
  const samples = [
    new Uint8Array([]),
    new Uint8Array([0, 0, 0]),
    new TextEncoder().encode('quantum webpages'),
    new Uint8Array(Array.from({ length: 64 }, (_, i) => (i * 37) % 256)),
  ];
  for (const bytes of samples) {
    assert.deepEqual(decodeQuanta(encodeQuanta(bytes), bytes.length), bytes);
  }
});

test('XNOR fabric compares spin first, then qubit', () => {
  const a = Array.from({ length: 8 }, (_, i) => stateToQuanta(i % QUANTA_STATE_COUNT));
  const same = resolveXnorFabric(a, a);
  assert.ok(same.spinMask.every((b) => b === 1));
  assert.ok(same.qubitMask.every((b) => b === 1));
  assert.ok(same.resolved.every((b) => b === 1));

  const flipped = a.map((q, i) =>
    i % 2 === 0 ? { ...q, qubit: q.qubit === 0 ? 1 : 0 } : q
  );
  const mixed = resolveXnorFabric(a, flipped);
  assert.ok(mixed.resolved.some((b) => b === 0));
  assert.notEqual(mixed.signature, same.signature);
});

test('collapse selects quanta from the resolved fabric', () => {
  const a = Array.from({ length: 4 }, (_, i) => stateToQuanta(i));
  const b = Array.from({ length: 4 }, (_, i) => stateToQuanta(5 - i));
  const fabric = resolveXnorFabric(a, b);
  const result = collapse(a, b, fabric);
  result.forEach((q, i) => {
    assert.deepEqual(q, fabric.resolved[i] === 1 ? a[i] : b[i]);
  });
});

test('channels are content-derived, not URLs', () => {
  const id = channelId('studio', 'karl');
  assert.ok(id.startsWith('qn:'));
  assert.equal(id, channelId('studio', 'karl'));
  assert.notEqual(id, channelId('studio', 'other'));
});

test('message chains validate and detect tampering', () => {
  const channel = channelId('studio');
  const first = createMessage(channel, 1, '(qpage "Studio")');
  const second = createMessage(channel, 2, '(text "hello")', first);
  assert.ok(chainValid(first, second));
  assert.equal(readMessage(first), '(qpage "Studio")');
  const tampered = { ...second, quanta: [...second.quanta].reverse() };
  assert.equal(chainValid(first, tampered), false);
});

test('fragments reassemble out of order across carriers', () => {
  const body =
    '(qpage "Long" ' +
    Array.from({ length: 40 }, (_, i) => `(text "line ${i}")`).join(' ') +
    ')';
  const message = createMessage(channelId('large'), 1, body);
  const fragments = fragmentMessage(message, 5);
  assert.ok(fragments.length > 1);
  const restored = reassembleMessage([...fragments].reverse());
  assert.ok(restored);
  assert.equal(restored.id, message.id);
  assert.equal(readMessage(restored), body);
});
