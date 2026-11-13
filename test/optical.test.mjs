import test from 'node:test';
import assert from 'node:assert/strict';

import {
  applyHomography,
  computeHomography,
  invertMat3,
  multiplyMat3,
  similarityHomography,
  createRgbImage,
  fillRect,
  warpPerspective,
  sampleBilinear,
  planarPoseFromPoints,
  projectCameraPoint,
  poseFromHomography,
  maximumInscribedCircle,
  pointInPolygon,
  distance,
} from '../dist/optical/perspective.js';
import {
  defaultLdpcCode,
  LdpcCode,
  llrFromBits,
  llrFromReliabilities,
} from '../dist/optical/fec.js';
import { bytesToBits, bitsToBytes, countBitErrors } from '../dist/util/bits.js';

const close = (actual, expected, tolerance) =>
  assert.ok(
    Math.abs(actual - expected) <= tolerance,
    `expected ${actual} ~= ${expected} (+/- ${tolerance})`
  );

test('four-point homography maps source corners onto destination corners', () => {
  const source = [
    { x: 0, y: 0 },
    { x: 100, y: 0 },
    { x: 100, y: 80 },
    { x: 0, y: 80 },
  ];
  const destination = [
    { x: 12, y: 9 },
    { x: 130, y: 20 },
    { x: 118, y: 105 },
    { x: 4, y: 90 },
  ];
  const H = computeHomography(source, destination);
  for (let i = 0; i < 4; i++) {
    const mapped = applyHomography(H, source[i]);
    close(mapped.x, destination[i].x, 1e-6);
    close(mapped.y, destination[i].y, 1e-6);
  }
});

test('homography inverse round-trips points', () => {
  const source = [
    { x: 0, y: 0 },
    { x: 40, y: 0 },
    { x: 40, y: 40 },
    { x: 0, y: 40 },
  ];
  const destination = [
    { x: 5, y: 7 },
    { x: 61, y: 3 },
    { x: 70, y: 52 },
    { x: 2, y: 48 },
  ];
  const H = computeHomography(source, destination);
  const inverse = invertMat3(H);
  const point = { x: 17.5, y: 22.25 };
  const there = applyHomography(H, point);
  const back = applyHomography(inverse, there);
  close(back.x, point.x, 1e-9);
  close(back.y, point.y, 1e-9);

  const identity = multiplyMat3(H, inverse);
  const similarity = [1, 0, 0, 0, 1, 0, 0, 0, 1];
  for (let i = 0; i < 9; i++) close(identity[i] / identity[8], similarity[i], 1e-9);
});

test('warpPerspective follows the supplied transform and fills outside white', () => {
  const source = createRgbImage(40, 40, [200, 200, 200]);
  fillRect(source, 10, 10, 20, 20, [20, 40, 60]);

  const identity = warpPerspective(source, similarityHomography(1), 40, 40);
  const [r, g, b] = sampleBilinear(identity, 20, 20);
  close(r, 20, 3);
  close(g, 40, 3);
  close(b, 60, 3);

  // Translate by 10 px: the patch should now sit at x=20..40.
  const moved = warpPerspective(source, similarityHomography(1, 10, 0), 60, 40);
  const movedCenter = sampleBilinear(moved, 30, 20);
  close(movedCenter[0], 20, 3);

  // The far edge is outside the source and must be background white.
  const beyond = warpPerspective(source, similarityHomography(1, 50, 0), 60, 40);
  const [wr, wg, wb] = sampleBilinear(beyond, 5, 20);
  assert.deepEqual([wr, wg, wb], [255, 255, 255]);
});

test('planar PnP recovers a synthetic camera pose', () => {
  const K = { fx: 800, fy: 800, cx: 320, cy: 240 };
  // Small rotation about x then y, camera looking down +z at the plane.
  const angle = 0.25;
  const rotation = [
    1, 0, 0,
    0, Math.cos(angle), -Math.sin(angle),
    0, Math.sin(angle), Math.cos(angle),
  ];
  const translation = { x: -0.4, y: 0.3, z: 5 };

  const worldPlanePoints = [
    { x: 0, y: 0 },
    { x: 1, y: 0 },
    { x: 1, y: 1 },
    { x: 0, y: 1 },
  ];
  const imagePoints = worldPlanePoints.map((point) =>
    projectCameraPoint(K, rotation, translation, { x: point.x, y: point.y, z: 0 })
  );

  const pose = planarPoseFromPoints(worldPlanePoints, imagePoints, K);
  close(pose.translation.x, translation.x, 1e-6);
  close(pose.translation.y, translation.y, 1e-6);
  close(pose.translation.z, translation.z, 1e-6);
  for (let i = 0; i < 9; i++) close(pose.rotation[i], rotation[i], 1e-6);

  // The recovered homography must agree with the input correspondences.
  for (let i = 0; i < 4; i++) {
    const mapped = applyHomography(pose.homography, worldPlanePoints[i]);
    close(mapped.x, imagePoints[i].x, 1e-6);
    close(mapped.y, imagePoints[i].y, 1e-6);
  }

  // poseFromHomography agrees with the direct path.
  const direct = poseFromHomography(
    computeHomography(worldPlanePoints, imagePoints),
    K
  );
  close(direct.translation.z, translation.z, 1e-6);
});

test('maximum inscribed circle of a square is centred with half-side radius', () => {
  const square = [
    { x: 0, y: 0 },
    { x: 100, y: 0 },
    { x: 100, y: 100 },
    { x: 0, y: 100 },
  ];
  const circle = maximumInscribedCircle(square);
  close(circle.center.x, 50, 1.5);
  close(circle.center.y, 50, 1.5);
  close(circle.radius, 50, 1.5);
  assert.ok(pointInPolygon(circle.center, square));
  assert.ok(!pointInPolygon({ x: -5, y: 50 }, square));
  assert.ok(distance(square[0], square[2]) > distance(square[0], square[1]));
});

test('LDPC encoding produces a valid systematic codeword', () => {
  const data = new Uint8Array(256);
  for (let i = 0; i < data.length; i++) data[i] = (i * 37 + 11) & 0xff;
  const codeword = defaultLdpcCode.encode(bytesToBits(data));

  assert.equal(codeword.length, defaultLdpcCode.n);
  assert.equal(defaultLdpcCode.n, 3072);
  assert.ok(defaultLdpcCode.isCodeword(codeword));
  // Systematic: the first k bits are the data bits.
  assert.deepEqual(Array.from(codeword.slice(0, 2048)), Array.from(bytesToBits(data)));
});

test('LDPC offset min-sum corrects spread bit errors', () => {
  const data = new Uint8Array(256);
  for (let i = 0; i < data.length; i++) data[i] = (i * 53 + 7) & 0xff;
  const codeword = defaultLdpcCode.encode(bytesToBits(data));

  for (const errorCount of [1, 5, 10, 20]) {
    const noisy = codeword.slice();
    for (let e = 0; e < errorCount; e++) noisy[(e * 613 + 17) % 3072] ^= 1;
    const llrs = llrFromBits(noisy, 0.05);
    const result = defaultLdpcCode.decode(llrs, 50);
    assert.ok(result.syndromeOk, `syndrome failed for ${errorCount} errors`);
    assert.equal(
      countBitErrors(bitsToBytes(result.dataBits), data),
      0,
      `data mismatch for ${errorCount} errors`
    );
  }
});

test('LDPC constructor validates parameters', () => {
  assert.throws(() => new LdpcCode({ rowWeight: 2 }), /rowWeight/);
  assert.throws(
    () => new LdpcCode({ k: 2048, m: 8, rowWeight: 3 }),
    /cover every data bit/
  );
  assert.throws(() => defaultLdpcCode.encode(new Uint8Array(2)), /data bits/);
  assert.throws(() => defaultLdpcCode.decode(new Float32Array(3)), /LLRs/);
  assert.throws(
    () => defaultLdpcCode.encodeBytes(new Uint8Array(2)),
    /data bytes/
  );
});

test('LLR helpers map hard bits and reliabilities consistently', () => {
  const bits = Uint8Array.from([0, 1, 0, 1]);
  const uniform = llrFromBits(bits, 0.1);
  assert.ok(uniform[0] > 0);
  assert.ok(uniform[1] < 0);
  const reliabilities = llrFromReliabilities(bits, [0.01, 0.01, 0.4, 0.4]);
  assert.ok(reliabilities[0] > 0);
  assert.ok(reliabilities[1] < 0);
  assert.ok(Math.abs(reliabilities[0]) > Math.abs(reliabilities[2]));
});
