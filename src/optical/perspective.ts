/**
 * Planar perspective geometry utilities.
 *
 * Retained as a standalone toolkit after spatial rendering was removed; the
 * photonic carrier does not use it. It models a planar target seen through an
 * arbitrary camera pose, so the plane appears as a quadrilateral:
 *
 *   - 4-point homography estimation (direct linear solve)
 *   - inversion / composition
 *   - bilinear image warping
 *   - planar pose decomposition from a homography and camera intrinsics
 *     (the PnP step for coplanar fiducials)
 *   - maximum inscribed circle (MIC) for choosing a safe render region
 *
 * Coordinates are in pixels with y pointing down, matching canvas/image
 * conventions. Camera intrinsics use the usual pinhole model with y down too.
 */

export interface Point2 {
  x: number;
  y: number;
}

export interface Vec3 {
  x: number;
  y: number;
  z: number;
}

/** Row-major 3x3 matrix: [m00, m01, m02, m10, ...]. */
export type Mat3 = number[];

/** Row-major RGB image, 3 bytes per pixel. */
export interface RgbImage {
  width: number;
  height: number;
  data: Uint8Array;
}

export interface CameraIntrinsics {
  fx: number;
  fy: number;
  cx: number;
  cy: number;
  skew?: number;
}

export interface PlanarPose {
  /** Rotation matrix, row-major 3x3. */
  rotation: Mat3;
  /** Translation in world units (same units as the planar points). */
  translation: Vec3;
  /** Homography from plane coordinates (z = 0) to image pixels. */
  homography: Mat3;
}

export const IDENTITY_MAT3: readonly number[] = [1, 0, 0, 0, 1, 0, 0, 0, 1];

export function mat3(values: ArrayLike<number>): Mat3 {
  if (values.length !== 9) throw new Error('Mat3 requires 9 values');
  return Array.from(values);
}

export function multiplyMat3(a: Mat3, b: Mat3): Mat3 {
  const out = new Array<number>(9);
  for (let row = 0; row < 3; row++) {
    for (let col = 0; col < 3; col++) {
      out[row * 3 + col] =
        a[row * 3] * b[col] +
        a[row * 3 + 1] * b[3 + col] +
        a[row * 3 + 2] * b[6 + col];
    }
  }
  return out;
}

/** Inverse via the adjugate. Throws for singular matrices. */
export function invertMat3(m: Mat3): Mat3 {
  const [a, b, c, d, e, f, g, h, i] = m;
  const A = e * i - f * h;
  const B = f * g - d * i;
  const C = d * h - e * g;
  const det = a * A + b * B + c * C;
  if (Math.abs(det) < 1e-12) throw new Error('matrix is singular');
  const invDet = 1 / det;
  return [
    A * invDet,
    (c * h - b * i) * invDet,
    (b * f - c * e) * invDet,
    B * invDet,
    (a * i - c * g) * invDet,
    (c * d - a * f) * invDet,
    C * invDet,
    (b * g - a * h) * invDet,
    (a * e - b * d) * invDet,
  ];
}

export function applyHomography(H: Mat3, point: Point2): Point2 {
  const w = H[6] * point.x + H[7] * point.y + H[8];
  if (Math.abs(w) < 1e-12) throw new Error('point maps to infinity');
  return {
    x: (H[0] * point.x + H[1] * point.y + H[2]) / w,
    y: (H[3] * point.x + H[4] * point.y + H[5]) / w,
  };
}

/** Transform a point by a 3x3 matrix without perspective division. */
export function multiplyMat3Vec3(m: Mat3, v: Vec3): Vec3 {
  return {
    x: m[0] * v.x + m[1] * v.y + m[2] * v.z,
    y: m[3] * v.x + m[4] * v.y + m[5] * v.z,
    z: m[6] * v.x + m[7] * v.y + m[8] * v.z,
  };
}

function solveLinearSystem(matrix: number[][], rhs: number[]): number[] {
  const n = rhs.length;
  const a = matrix.map((row, i) => [...row, rhs[i]]);
  for (let col = 0; col < n; col++) {
    let pivot = col;
    for (let row = col + 1; row < n; row++) {
      if (Math.abs(a[row][col]) > Math.abs(a[pivot][col])) pivot = row;
    }
    if (Math.abs(a[pivot][col]) < 1e-12) throw new Error('degenerate correspondence set');
    if (pivot !== col) [a[col], a[pivot]] = [a[pivot], a[col]];
    const divisor = a[col][col];
    for (let k = col; k <= n; k++) a[col][k] /= divisor;
    for (let row = 0; row < n; row++) {
      if (row === col) continue;
      const factor = a[row][col];
      if (factor === 0) continue;
      for (let k = col; k <= n; k++) a[row][k] -= factor * a[col][k];
    }
  }
  return a.map((row) => row[n]);
}

/**
 * Estimate the homography mapping four source points to four destination
 * points. Points must be given in corresponding order and must not be
 * collinear (three of them).
 */
export function computeHomography(source: Point2[], destination: Point2[]): Mat3 {
  if (source.length !== 4 || destination.length !== 4) {
    throw new Error('homography needs exactly four point pairs');
  }
  const matrix: number[][] = [];
  const rhs: number[] = [];
  for (let i = 0; i < 4; i++) {
    const { x, y } = source[i];
    const { x: u, y: v } = destination[i];
    matrix.push([x, y, 1, 0, 0, 0, -u * x, -u * y]);
    rhs.push(u);
    matrix.push([0, 0, 0, x, y, 1, -v * x, -v * y]);
    rhs.push(v);
  }
  const h = solveLinearSystem(matrix, rhs);
  return [...h, 1];
}

/** Apply a homography to a planar (z = 0) point, returning pixels. */
export function projectPlanePoint(H: Mat3, point: Point2): Point2 {
  return applyHomography(H, point);
}

/** Homography for a pure translation/scale, useful for fixtures. */
export function similarityHomography(scale: number, tx = 0, ty = 0): Mat3 {
  return [scale, 0, tx, 0, scale, ty, 0, 0, 1];
}

/** Intrinsics matrix K. */
export function intrinsicsMatrix(K: CameraIntrinsics): Mat3 {
  return [K.fx, K.skew ?? 0, K.cx, 0, K.fy, K.cy, 0, 0, 1];
}

/**
 * Decompose a plane-to-image homography into a camera pose:
 *
 *   H = s * K * [r1 r2 t]   for world points (X, Y, 0)
 *
 * The sign of the translation is chosen so the plane sits in front of the
 * camera (t.z > 0). r1/r2 are re-orthonormalised to absorb estimation noise.
 */
export function poseFromHomography(H: Mat3, K: CameraIntrinsics): PlanarPose {
  const Kinv = invertMat3(intrinsicsMatrix(K));
  const a = multiplyMat3(Kinv, H);

  const n1 = Math.hypot(a[0], a[3], a[6]);
  const n2 = Math.hypot(a[1], a[4], a[7]);
  if (n1 < 1e-12 || n2 < 1e-12) throw new Error('degenerate homography');

  let lambda = 2 / (n1 + n2);
  if (a[2] * lambda < 0) lambda = -lambda;
  if (a[2] === 0) lambda = Math.abs(lambda);

  let r1: Vec3 = { x: a[0] * lambda, y: a[3] * lambda, z: a[6] * lambda };
  let r2: Vec3 = { x: a[1] * lambda, y: a[4] * lambda, z: a[7] * lambda };
  let t: Vec3 = { x: a[2] * lambda, y: a[5] * lambda, z: a[8] * lambda };

  const norm1 = Math.hypot(r1.x, r1.y, r1.z);
  r1 = { x: r1.x / norm1, y: r1.y / norm1, z: r1.z / norm1 };
  const dot = r1.x * r2.x + r1.y * r2.y + r1.z * r2.z;
  r2 = {
    x: r2.x - dot * r1.x,
    y: r2.y - dot * r1.y,
    z: r2.z - dot * r1.z,
  };
  const norm2 = Math.hypot(r2.x, r2.y, r2.z);
  r2 = { x: r2.x / norm2, y: r2.y / norm2, z: r2.z / norm2 };
  const r3: Vec3 = {
    x: r1.y * r2.z - r1.z * r2.y,
    y: r1.z * r2.x - r1.x * r2.z,
    z: r1.x * r2.y - r1.y * r2.x,
  };

  if (t.z < 0) {
    // Camera looks along -z for this homography. Flip the pose so the plane
    // sits in front of the camera. Negating r1 and r2 keeps r3 = r1 × r2
    // unchanged, so the rotation stays proper (det = +1).
    r1 = { x: -r1.x, y: -r1.y, z: -r1.z };
    r2 = { x: -r2.x, y: -r2.y, z: -r2.z };
    t = { x: -t.x, y: -t.y, z: -t.z };
  }

  const rotation: Mat3 = [
    r1.x, r2.x, r3.x,
    r1.y, r2.y, r3.y,
    r1.z, r2.z, r3.z,
  ];
  return { rotation, translation: t, homography: H };
}

/**
 * PnP for four coplanar world points (z = 0) and their image projections.
 * This is the planar PnP used for corner fiducials.
 */
export function planarPoseFromPoints(
  worldPlanePoints: Point2[],
  imagePoints: Point2[],
  K: CameraIntrinsics
): PlanarPose {
  const H = computeHomography(worldPlanePoints, imagePoints);
  return poseFromHomography(H, K);
}

/** Project a 3D point with K [R|t]. */
export function projectCameraPoint(
  K: CameraIntrinsics,
  rotation: Mat3,
  translation: Vec3,
  point: Vec3
): Point2 {
  const camera = {
    x: rotation[0] * point.x + rotation[1] * point.y + rotation[2] * point.z + translation.x,
    y: rotation[3] * point.x + rotation[4] * point.y + rotation[5] * point.z + translation.y,
    z: rotation[6] * point.x + rotation[7] * point.y + rotation[8] * point.z + translation.z,
  };
  if (Math.abs(camera.z) < 1e-12) throw new Error('point is on the camera plane');
  return {
    x: (K.fx * camera.x + (K.skew ?? 0) * camera.y) / camera.z + K.cx,
    y: (K.fy * camera.y) / camera.z + K.cy,
  };
}

function clamp(value: number, min: number, max: number): number {
  return value < min ? min : value > max ? max : value;
}

function sampleChannel(image: RgbImage, channel: number, x: number, y: number): number {
  const x0 = clamp(Math.floor(x), 0, image.width - 1);
  const y0 = clamp(Math.floor(y), 0, image.height - 1);
  const x1 = clamp(x0 + 1, 0, image.width - 1);
  const y1 = clamp(y0 + 1, 0, image.height - 1);
  const fx = clamp(x - x0, 0, 1);
  const fy = clamp(y - y0, 0, 1);
  const at = (px: number, py: number) => image.data[(py * image.width + px) * 3 + channel];
  const top = at(x0, y0) * (1 - fx) + at(x1, y0) * fx;
  const bottom = at(x0, y1) * (1 - fx) + at(x1, y1) * fx;
  return top * (1 - fy) + bottom * fy;
}

/** Bilinear RGB sample. Returns [r, g, b] as floating point values. */
export function sampleBilinear(image: RgbImage, x: number, y: number): [number, number, number] {
  return [
    sampleChannel(image, 0, x, y),
    sampleChannel(image, 1, x, y),
    sampleChannel(image, 2, x, y),
  ];
}

/** Bilinear grayscale sample (Rec. 601 luma). */
export function sampleGrayscale(image: RgbImage, x: number, y: number): number {
  const [r, g, b] = sampleBilinear(image, x, y);
  return 0.299 * r + 0.587 * g + 0.114 * b;
}

export function toGrayscaleImage(image: RgbImage): { width: number; height: number; data: Float32Array } {
  const data = new Float32Array(image.width * image.height);
  for (let i = 0; i < data.length; i++) {
    data[i] =
      0.299 * image.data[i * 3] +
      0.587 * image.data[i * 3 + 1] +
      0.114 * image.data[i * 3 + 2];
  }
  return { width: image.width, height: image.height, data };
}

/** Warp `source` into an output image using bilinear sampling. */
export function warpPerspective(
  source: RgbImage,
  H: Mat3,
  outWidth: number,
  outHeight: number,
  background: [number, number, number] = [255, 255, 255]
): RgbImage {
  const inverse = invertMat3(H);
  const out = new Uint8Array(outWidth * outHeight * 3);
  for (let y = 0; y < outHeight; y++) {
    for (let x = 0; x < outWidth; x++) {
      const mapped = applyHomography(inverse, { x: x + 0.5, y: y + 0.5 });
      const index = (y * outWidth + x) * 3;
      if (
        mapped.x < -0.5 ||
        mapped.y < -0.5 ||
        mapped.x > source.width - 0.5 ||
        mapped.y > source.height - 0.5
      ) {
        out[index] = background[0];
        out[index + 1] = background[1];
        out[index + 2] = background[2];
        continue;
      }
      const [r, g, b] = sampleBilinear(source, mapped.x - 0.5, mapped.y - 0.5);
      out[index] = clamp(Math.round(r), 0, 255);
      out[index + 1] = clamp(Math.round(g), 0, 255);
      out[index + 2] = clamp(Math.round(b), 0, 255);
    }
  }
  return { width: outWidth, height: outHeight, data: out };
}

export function createRgbImage(width: number, height: number, fill: [number, number, number] = [0, 0, 0]): RgbImage {
  const data = new Uint8Array(width * height * 3);
  for (let i = 0; i < width * height; i++) {
    data[i * 3] = fill[0];
    data[i * 3 + 1] = fill[1];
    data[i * 3 + 2] = fill[2];
  }
  return { width, height, data };
}

/** Fill an axis-aligned rectangle in an RGB image. */
export function fillRect(
  image: RgbImage,
  x: number,
  y: number,
  width: number,
  height: number,
  color: [number, number, number]
): void {
  const x0 = clamp(Math.round(x), 0, image.width);
  const y0 = clamp(Math.round(y), 0, image.height);
  const x1 = clamp(Math.round(x + width), 0, image.width);
  const y1 = clamp(Math.round(y + height), 0, image.height);
  for (let py = y0; py < y1; py++) {
    for (let px = x0; px < x1; px++) {
      const index = (py * image.width + px) * 3;
      image.data[index] = color[0];
      image.data[index + 1] = color[1];
      image.data[index + 2] = color[2];
    }
  }
}

/** Point-in-polygon (ray casting). */
export function pointInPolygon(point: Point2, polygon: Point2[]): boolean {
  let inside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const a = polygon[i];
    const b = polygon[j];
    if (a.y > point.y !== b.y > point.y) {
      const x = ((b.x - a.x) * (point.y - a.y)) / (b.y - a.y) + a.x;
      if (point.x < x) inside = !inside;
    }
  }
  return inside;
}

function pointSegmentDistance(p: Point2, a: Point2, b: Point2): number {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const lengthSq = dx * dx + dy * dy;
  if (lengthSq === 0) return Math.hypot(p.x - a.x, p.y - a.y);
  const t = clamp(((p.x - a.x) * dx + (p.y - a.y) * dy) / lengthSq, 0, 1);
  return Math.hypot(p.x - (a.x + t * dx), p.y - (a.y + t * dy));
}

export interface InscribedCircle {
  center: Point2;
  radius: number;
}

/**
 * Largest circle fully contained in a convex polygon.
 *
 * A coarse grid search followed by local refinement keeps this cheap enough
 * for per-frame use while staying deterministic. The polygon is expected in
 * display/pixel coordinates.
 */
export function maximumInscribedCircle(
  polygon: Point2[],
  gridSize = 256
): InscribedCircle {
  if (polygon.length < 3) throw new Error('polygon needs at least three points');
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const p of polygon) {
    minX = Math.min(minX, p.x);
    minY = Math.min(minY, p.y);
    maxX = Math.max(maxX, p.x);
    maxY = Math.max(maxY, p.y);
  }
  const width = maxX - minX;
  const height = maxY - minY;
  const step = Math.max(width, height) / gridSize;
  if (!(step > 0)) throw new Error('degenerate polygon');

  let best: InscribedCircle = { center: { x: minX, y: minY }, radius: -1 };
  let search = { minX, minY, maxX, maxY, step };

  for (let pass = 0; pass < 3; pass++) {
    for (let y = search.minY; y <= search.maxY; y += search.step) {
      for (let x = search.minX; x <= search.maxX; x += search.step) {
        const point = { x, y };
        if (!pointInPolygon(point, polygon)) continue;
        let radius = Infinity;
        for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
          radius = Math.min(radius, pointSegmentDistance(point, polygon[j], polygon[i]));
        }
        if (radius > best.radius) best = { center: point, radius };
      }
    }
    search = {
      minX: best.center.x - search.step * 2,
      minY: best.center.y - search.step * 2,
      maxX: best.center.x + search.step * 2,
      maxY: best.center.y + search.step * 2,
      step: search.step / 8,
    };
  }
  return best;
}

/** Scale a polygon about its centroid (positive factor shrinks/expands). */
export function scalePolygon(polygon: Point2[], factor: number): Point2[] {
  let cx = 0;
  let cy = 0;
  for (const p of polygon) {
    cx += p.x;
    cy += p.y;
  }
  cx /= polygon.length;
  cy /= polygon.length;
  return polygon.map((p) => ({
    x: cx + (p.x - cx) * factor,
    y: cy + (p.y - cy) * factor,
  }));
}

export function distance(a: Point2, b: Point2): number {
  return Math.hypot(a.x - b.x, a.y - b.y);
}
