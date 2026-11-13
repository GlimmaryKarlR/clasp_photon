import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createSpatialLayout,
  renderSpatialFrame,
  renderAndWarp,
  detectFinders,
  finderOrderings,
  payloadQuadFromFinders,
  sampleSpatialFrame,
  decodeSpatialFrame,
  rectifySpatialFrame,
  otsuThreshold,
  twoClusterThreshold,
  SPATIAL_CODEWORD_BITS,
  SPATIAL_CODEWORD_BYTES,
} from '../dist/optical/spatial.js';
import { defaultLdpcCode } from '../dist/optical/fec.js';
import {
  computeHomography,
  warpPerspective,
  createRgbImage,
} from '../dist/optical/perspective.js';
import { bytesToBits, bitsToBytes, countBitErrors } from '../dist/util/bits.js';

const data = new Uint8Array(256);
for (let i = 0; i < data.length; i++) data[i] = (i * 37 + 11) & 0xff;
const codeword = defaultLdpcCode.encode(bytesToBits(data));
const expectedBytes = bitsToBytes(codeword);

const frameSource = () => [
  { x: 0, y: 0 },
  { x: 320, y: 0 },
  { x: 320, y: 320 },
  { x: 0, y: 320 },
];

function rotateWarp(degrees, scale = 1, out = 500) {
  const source = frameSource();
  const radians = (degrees * Math.PI) / 180;
  const map = (x, y) => ({
    x: out / 2 + ((x - 160) * Math.cos(radians) - (y - 160) * Math.sin(radians)) * scale,
    y: out / 2 + ((x - 160) * Math.sin(radians) + (y - 160) * Math.cos(radians)) * scale,
  });
  const destination = source.map((point) => map(point.x, point.y));
  return { H: computeHomography(source, destination), out };
}

test('spatial dimensions match one LDPC codeword', () => {
  assert.equal(SPATIAL_CODEWORD_BITS, 3072);
  assert.equal(SPATIAL_CODEWORD_BYTES, 384);
  assert.equal(codeword.length, SPATIAL_CODEWORD_BITS);
});

test('unwarped frame round-trips with zero bit errors', () => {
  const frame = renderSpatialFrame(codeword);
  assert.equal(frame.image.width, 320);
  assert.equal(frame.image.height, 320);

  const sampled = sampleSpatialFrame(frame.image, frame.payloadQuad);
  assert.equal(countBitErrors(sampled.bytes, expectedBytes), 0);
  assert.ok(sampled.thresholds.every((t) => t > 0 && t < 255));
});

test('finder detection returns the four corner markers', () => {
  const frame = renderSpatialFrame(codeword);
  const detection = detectFinders(frame.image);
  assert.ok(detection);
  const expected = frame.finderCenters;
  for (let i = 0; i < 4; i++) {
    const match = detection.centers.some(
      (center) => Math.hypot(center.x - expected[i].x, center.y - expected[i].y) < 3
    );
    assert.ok(match, `missing finder ${i}`);
  }
});

test('decodeSpatialFrame recovers an unwarped frame', () => {
  const frame = renderSpatialFrame(codeword);
  const decoded = decodeSpatialFrame(
    frame.image,
    (sampled) => countBitErrors(sampled.bytes, expectedBytes) < 100
  );
  assert.ok(decoded);
  assert.equal(countBitErrors(decoded.bytes, expectedBytes), 0);
});

test('decodeSpatialFrame corrects perspective, rotation and scaling', () => {
  const source = frameSource();
  const cases = [
    [
      { x: 70, y: 50 },
      { x: 430, y: 80 },
      { x: 400, y: 360 },
      { x: 40, y: 330 },
    ],
    [
      { x: 100, y: 60 },
      { x: 400, y: 60 },
      { x: 400, y: 340 },
      { x: 100, y: 340 },
    ],
  ];

  for (const destination of cases) {
    const warped = warpPerspective(
      renderSpatialFrame(codeword).image,
      computeHomography(source, destination),
      500,
      420
    );
    const decoded = decodeSpatialFrame(
      warped,
      (sampled) => countBitErrors(sampled.bytes, expectedBytes) < 200
    );
    assert.ok(decoded, 'failed to decode perspective warp');
    assert.equal(countBitErrors(decoded.bytes, expectedBytes), 0);
  }

  for (const degrees of [0, 15, 45, 90, 180, 270]) {
    const { H, out } = rotateWarp(degrees);
    const warped = warpPerspective(renderSpatialFrame(codeword).image, H, out, out);
    const decoded = decodeSpatialFrame(
      warped,
      (sampled) => countBitErrors(sampled.bytes, expectedBytes) < 200
    );
    assert.ok(decoded, `failed to decode rotation ${degrees}`);
    assert.equal(countBitErrors(decoded.bytes, expectedBytes), 0);
  }

  const { H, out } = rotateWarp(35, 0.55);
  const scaled = warpPerspective(renderSpatialFrame(codeword).image, H, out, out);
  assert.ok(
    decodeSpatialFrame(
      scaled,
      (sampled) => countBitErrors(sampled.bytes, expectedBytes) < 300
    )
  );
});

test('both finder windings are offered and one is correct', () => {
  const frame = renderSpatialFrame(codeword);
  const detection = detectFinders(frame.image);
  assert.ok(detection);
  const orderings = finderOrderings(detection);
  assert.equal(orderings.length, 2);

  const errors = orderings.map((finders) => {
    const quad = payloadQuadFromFinders(finders);
    return countBitErrors(sampleSpatialFrame(frame.image, quad).bytes, expectedBytes);
  });
  assert.ok(errors.includes(0), `no winding decoded cleanly: ${errors.join(', ')}`);
});

test('spatial frame tolerates sensor noise', () => {
  for (const noiseStdDev of [10, 25, 40]) {
    const frame = renderSpatialFrame(codeword, { noiseStdDev, noiseSeed: 4242 });
    const decoded = decodeSpatialFrame(
      frame.image,
      (sampled) => countBitErrors(sampled.bytes, expectedBytes) < 300
    );
    assert.ok(decoded, `failed at noise ${noiseStdDev}`);
    // The LDPC decoder cleans up the residual optical errors.
    const llrs = new Float32Array(3072);
    for (let i = 0; i < 3072; i++) {
      const value = decoded.errorProbabilities[i];
      const magnitude = Math.log((1 - value) / value);
      llrs[i] = decoded.bits[i] ? -magnitude : magnitude;
    }
    const result = defaultLdpcCode.decode(llrs, 50);
    assert.ok(result.syndromeOk, `LDPC failed at noise ${noiseStdDev}`);
    assert.equal(countBitErrors(bitsToBytes(result.dataBits), data), 0);
  }
});

test('rectification produces an upright payload-only image', () => {
  const frame = renderSpatialFrame(codeword);
  const rectified = rectifySpatialFrame(frame.image, frame.payloadQuad);
  assert.equal(rectified.width, 256);
  assert.equal(rectified.height, 256);

  // Sample the rectified image with a payload-sized quad.
  const quad = [
    { x: 0, y: 0 },
    { x: 256, y: 0 },
    { x: 256, y: 256 },
    { x: 0, y: 256 },
  ];
  const sampled = sampleSpatialFrame(rectified, quad);
  assert.ok(countBitErrors(sampled.bytes, expectedBytes) < 20);
});

test('renderAndWarp composes rendering with an output homography', () => {
  const { H, out } = rotateWarp(20, 0.7);
  const warped = renderAndWarp(codeword, H, { outWidth: out, outHeight: out });
  assert.equal(warped.width, out);
  assert.equal(warped.height, out);
  assert.ok(
    decodeSpatialFrame(
      warped,
      (sampled) => countBitErrors(sampled.bytes, expectedBytes) < 300
    )
  );
});

test('thresholds separate the two spatial levels', () => {
  const values = new Float32Array(200);
  for (let i = 0; i < 100; i++) values[i] = 24;
  for (let i = 100; i < 200; i++) values[i] = 232;
  const otsu = otsuThreshold(values);
  const refined = twoClusterThreshold(values);
  assert.ok(otsu >= 24 && otsu < 232);
  assert.ok(refined > otsu && refined < 232);
  assert.ok(Math.abs(refined - 128) < 1e-6);
});

test('blank frames do not produce a finder detection', () => {
  assert.equal(detectFinders(createRgbImage(240, 240, [255, 255, 255])), null);
});

test('spatial layout geometry is self-consistent', () => {
  const layout = createSpatialLayout(8);
  assert.equal(layout.width, 320);
  assert.equal(layout.payloadOrigin.x, 32);
  assert.equal(layout.finderPlaneCenters.length, 4);
  const quad = payloadQuadFromFinders(
    layout.finderPlaneCenters.map((p) => ({
      x: layout.payloadOrigin.x + p.x * layout.cellPixels,
      y: layout.payloadOrigin.y + p.y * layout.cellPixels,
    })),
    layout
  );
  assert.deepEqual(
    quad.map((p) => [Math.round(p.x), Math.round(p.y)]),
    [
      [32, 32],
      [288, 32],
      [288, 288],
      [32, 288],
    ]
  );
});
