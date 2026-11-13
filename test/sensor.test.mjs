import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildCameraConstraints,
  FrameClock,
} from '../dist/sensor/cameraSensor.js';

test('camera constraints apply manual exposure, ISO, focus and white balance', () => {
  const capabilities = {
    exposureMode: ['continuous', 'manual'],
    exposureTime: { min: 1, max: 1000, step: 1 },
    iso: { min: 50, max: 3200, step: 1 },
    focusMode: ['auto', 'manual'],
    focusDistance: { min: 0, max: 10 },
    whiteBalanceMode: ['auto', 'manual'],
    colorTemperature: { min: 2500, max: 9000 },
  };
  const plan = buildCameraConstraints(capabilities, {
    targetFps: 24,
    iso: 400,
    exposureTime: 12,
    focusDistance: 2,
    colorTemperature: 4200,
  });

  const constraints = plan.videoConstraints;
  assert.equal(constraints.frameRate?.max, 24);
  assert.equal(constraints.exposureMode, 'manual');
  assert.equal(constraints.iso, 400);
  assert.equal(constraints.focusMode, 'manual');
  assert.equal(constraints.whiteBalanceMode, 'manual');
  assert.equal(constraints.colorTemperature, 4200);
  // Out-of-range values are clamped to the reported capability range.
  assert.equal(constraints.exposureTime, 12);
  assert.ok(plan.skipped.length === 0, plan.skipped.join(','));
});

test('camera constraints clamp values and report unsupported controls', () => {
  const plan = buildCameraConstraints(
    {
      exposureMode: ['continuous'],
      iso: { min: 100, max: 800 },
    },
    { exposureTime: 9999, iso: 6400, rearCamera: false }
  );
  const constraints = plan.videoConstraints;
  // iso is clamped to the maximum reported value.
  assert.equal(constraints.iso, 800);
  assert.ok(!('exposureMode' in constraints));
  assert.ok(!('focusMode' in constraints));
  assert.ok(plan.skipped.some((entry) => entry.includes('exposureMode')));
  assert.ok(plan.skipped.some((entry) => entry.includes('focusMode')));
});

test('camera constraints request the rear camera by default', () => {
  const plan = buildCameraConstraints({});
  const constraints = plan.videoConstraints;
  assert.deepEqual(constraints.facingMode, { ideal: 'environment' });
  assert.ok(plan.applied.includes('facingMode'));
});

test('FrameClock tracks interval statistics and jitter', () => {
  const clock = new FrameClock(60);
  // 60 fps with a deterministic 1 ms jitter pattern.
  const timestamps = [0, 16, 33, 50, 67, 83, 100];
  for (const timestamp of timestamps) clock.tick(timestamp);
  const stats = clock.stats();

  assert.equal(stats.frames, timestamps.length);
  assert.equal(stats.durationMs, 100);
  // Intervals: 16,17,17,17,16,17 -> mean 16.666..., ~60 fps.
  assert.ok(Math.abs(stats.meanIntervalMs - 100 / 6) < 1e-9);
  assert.ok(Math.abs(stats.fps - 60) < 0.01);
  assert.ok(stats.jitterMs >= 0 && stats.jitterMs < 1);
});

test('FrameClock reports zero-valued stats before any frame', () => {
  const clock = new FrameClock(30);
  assert.deepEqual(clock.stats(), {
    frames: 0,
    durationMs: 0,
    fps: 0,
    meanIntervalMs: 0,
    jitterMs: 0,
  });
  assert.equal(clock.stop().frames, 0);
});
