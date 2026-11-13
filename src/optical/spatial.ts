/**
 * Spatial RGB modulation for the camera photonic path.
 *
 * A frame is a 32x32 grid of cells. Each cell carries three independent bits,
 * one per colour channel, so one frame holds 32 * 32 * 3 = 3072 codeword bits
 * (exactly one LDPC codeword from `fec.ts`).
 *
 * Geometry:
 *
 *   - 32x32 payload cells, `cellPixels` pixels each
 *   - a one-cell white gap around the payload
 *   - four dark finder squares in the corners: the top-left one is 2x2 cells,
 *     the other three are 3x3 cells, so orientation is unambiguous
 *
 * Rendering writes each RGB channel at one of two levels. Detection locates
 * the finder squares, builds a payload homography, samples every cell centre
 * and recovers the bits with a per-channel Otsu threshold. This is the
 * perspective-corrected inverse warp described in the QuaNet architecture.
 */

import {
  type Mat3,
  type Point2,
  type RgbImage,
  applyHomography,
  computeHomography,
  createRgbImage,
  fillRect,
  sampleBilinear,
  toGrayscaleImage,
  warpPerspective,
} from './perspective.js';
import { bitsToBytes } from '../util/bits.js';

export const SPATIAL_GRID = 32;
export const SPATIAL_BITS_PER_CELL = 3;
export const SPATIAL_CODEWORD_BITS = SPATIAL_GRID * SPATIAL_GRID * SPATIAL_BITS_PER_CELL;
export const SPATIAL_CODEWORD_BYTES = SPATIAL_CODEWORD_BITS / 8;
export const SPATIAL_FINDER_CELLS = 3;
export const SPATIAL_MARGIN_CELLS = 4;

export interface SpatialLayout {
  gridSize: number;
  cellPixels: number;
  marginCells: number;
  finderCells: number;
  width: number;
  height: number;
  /** Pixel position of payload cell (0, 0). */
  payloadOrigin: Point2;
  /** Payload plane corner coordinates (cell units). */
  planeCorners: [Point2, Point2, Point2, Point2];
  /** Finder centres in payload-plane cell coordinates, TL/TR/BR/BL. */
  finderPlaneCenters: [Point2, Point2, Point2, Point2];
  /** Finder half extents in cell units (TL is smaller). */
  finderHalfExtents: [number, number, number, number];
}

export function createSpatialLayout(cellPixels = 8, gridSize = SPATIAL_GRID): SpatialLayout {
  const marginCells = SPATIAL_MARGIN_CELLS;
  const width = (gridSize + marginCells * 2) * cellPixels;
  const height = width;
  const origin = marginCells * cellPixels;
  return {
    gridSize,
    cellPixels,
    marginCells,
    finderCells: SPATIAL_FINDER_CELLS,
    width,
    height,
    payloadOrigin: { x: origin, y: origin },
    planeCorners: [
      { x: 0, y: 0 },
      { x: gridSize, y: 0 },
      { x: gridSize, y: gridSize },
      { x: 0, y: gridSize },
    ],
    finderPlaneCenters: [
      { x: -2, y: -2 },
      { x: gridSize + 2.5, y: -2.5 },
      { x: gridSize + 2.5, y: gridSize + 2.5 },
      { x: -2, y: gridSize + 2.5 },
    ],
    finderHalfExtents: [1, 1.5, 1.5, 1.5],
  };
}

/** Convert payload-plane coordinates (cell units) to pixels. */
export function planeToPixel(layout: SpatialLayout, point: Point2): Point2 {
  return {
    x: layout.payloadOrigin.x + point.x * layout.cellPixels,
    y: layout.payloadOrigin.y + point.y * layout.cellPixels,
  };
}

/** Pixel quad occupied by the payload, TL/TR/BR/BL. */
export function payloadPixelQuad(layout: SpatialLayout): [Point2, Point2, Point2, Point2] {
  return layout.planeCorners.map((p) => planeToPixel(layout, p)) as [
    Point2,
    Point2,
    Point2,
    Point2,
  ];
}

/** Finder centres in pixels for an unwarped frame, TL/TR/BR/BL. */
export function finderPixelCenters(layout: SpatialLayout): [Point2, Point2, Point2, Point2] {
  return layout.finderPlaneCenters.map((p) => planeToPixel(layout, p)) as [
    Point2,
    Point2,
    Point2,
    Point2,
  ];
}

/** Bit index for cell (x, y), channel 0=R, 1=G, 2=B. */
export function cellBitIndex(x: number, y: number, channel: number, gridSize = SPATIAL_GRID): number {
  return (y * gridSize + x) * SPATIAL_BITS_PER_CELL + channel;
}

export interface RenderOptions {
  cellPixels?: number;
  /** RGB level for bit 0 (default 24). */
  low?: number;
  /** RGB level for bit 1 (default 232). */
  high?: number;
  /** Additive Gaussian-ish noise, in colour levels. */
  noiseStdDev?: number;
  /** Optional deterministic noise seed. */
  noiseSeed?: number;
  /** Border/background colour (default white). */
  background?: [number, number, number];
  /** Paint the finder squares (default true). */
  finders?: boolean;
}

export interface RenderedSpatialFrame {
  image: RgbImage;
  layout: SpatialLayout;
  payloadQuad: [Point2, Point2, Point2, Point2];
  finderCenters: [Point2, Point2, Point2, Point2];
  /** Homography from payload-plane cell coordinates to image pixels. */
  planeToImage: Mat3;
}

function gaussian(random: () => number): number {
  // Box-Muller, deterministic given the PRNG.
  const u1 = Math.max(1e-9, random() / 0x100000000);
  const u2 = random() / 0x100000000;
  return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
}

function makeNoiseRandom(seed: number): () => number {
  let state = seed >>> 0 || 0x9e3779b9;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state;
  };
}

/** Render a 3072-bit codeword as an RGB spatial frame. */
export function renderSpatialFrame(
  codewordBits: Uint8Array,
  options: RenderOptions = {}
): RenderedSpatialFrame {
  if (codewordBits.length !== SPATIAL_CODEWORD_BITS) {
    throw new Error(`expected ${SPATIAL_CODEWORD_BITS} codeword bits, got ${codewordBits.length}`);
  }
  const layout = createSpatialLayout(options.cellPixels ?? 8);
  const low = options.low ?? 24;
  const high = options.high ?? 232;
  const background = options.background ?? [255, 255, 255];
  const image = createRgbImage(layout.width, layout.height, background);

  // Payload cells.
  for (let y = 0; y < layout.gridSize; y++) {
    for (let x = 0; x < layout.gridSize; x++) {
      const px = layout.payloadOrigin.x + x * layout.cellPixels;
      const py = layout.payloadOrigin.y + y * layout.cellPixels;
      const r = codewordBits[cellBitIndex(x, y, 0, layout.gridSize)] ? high : low;
      const g = codewordBits[cellBitIndex(x, y, 1, layout.gridSize)] ? high : low;
      const b = codewordBits[cellBitIndex(x, y, 2, layout.gridSize)] ? high : low;
      fillRect(image, px, py, layout.cellPixels, layout.cellPixels, [r, g, b]);
    }
  }

  // Finder squares.
  if (options.finders !== false) {
    layout.finderPlaneCenters.forEach((center, index) => {
      const half = layout.finderHalfExtents[index];
      const topLeft = planeToPixel(layout, { x: center.x - half, y: center.y - half });
      const size = half * 2 * layout.cellPixels;
      fillRect(image, topLeft.x, topLeft.y, size, size, [0, 0, 0]);
    });
  }

  if (options.noiseStdDev && options.noiseStdDev > 0) {
    const random = makeNoiseRandom(options.noiseSeed ?? 0x1234567);
    for (let i = 0; i < image.data.length; i++) {
      const value = image.data[i] + gaussian(random) * options.noiseStdDev;
      image.data[i] = Math.max(0, Math.min(255, Math.round(value)));
    }
  }

  const planeToImage = computeHomography(
    layout.planeCorners,
    payloadPixelQuad(layout)
  );
  return {
    image,
    layout,
    payloadQuad: payloadPixelQuad(layout),
    finderCenters: finderPixelCenters(layout),
    planeToImage,
  };
}

interface Component {
  area: number;
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
  cx: number;
  cy: number;
}

/**
 * Connected-component search over dark pixels. Finder squares are the only
 * large dark objects in the frame border, so they survive filtering even when
 * the payload itself contains dark cells.
 */
export function findDarkComponents(
  image: RgbImage,
  options: { threshold?: number; minArea?: number; maxArea?: number } = {}
): Component[] {
  const threshold = options.threshold ?? 80;
  const minArea = options.minArea ?? 120;
  const maxArea = options.maxArea ?? Math.max(200, (image.width * image.height) / 4);
  const gray = toGrayscaleImage(image);
  const visited = new Uint8Array(image.width * image.height);
  const components: Component[] = [];
  const stack: number[] = [];

  for (let start = 0; start < visited.length; start++) {
    if (visited[start] || gray.data[start] >= threshold) continue;
    let area = 0;
    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;
    let sumX = 0;
    let sumY = 0;
    stack.length = 0;
    stack.push(start);
    visited[start] = 1;

    while (stack.length > 0) {
      const index = stack.pop()!;
      const x = index % image.width;
      const y = Math.floor(index / image.width);
      area++;
      sumX += x;
      sumY += y;
      minX = Math.min(minX, x);
      minY = Math.min(minY, y);
      maxX = Math.max(maxX, x);
      maxY = Math.max(maxY, y);
      const neighbours = [index - 1, index + 1, index - image.width, index + image.width];
      for (let n = 0; n < neighbours.length; n++) {
        const next = neighbours[n];
        if (next < 0 || next >= visited.length) continue;
        if (n === 0 && x === 0) continue;
        if (n === 1 && x === image.width - 1) continue;
        if (visited[next] || gray.data[next] >= threshold) continue;
        visited[next] = 1;
        stack.push(next);
      }
    }

    if (area < minArea || area > maxArea) continue;
    const width = maxX - minX + 1;
    const height = maxY - minY + 1;
    const aspect = width / height;
    const fill = area / (width * height);
    if (aspect < 0.3 || aspect > 3.3 || fill < 0.35) continue;
    components.push({
      area,
      minX,
      minY,
      maxX,
      maxY,
      cx: sumX / area,
      cy: sumY / area,
    });
  }

  return components.sort((a, b) => b.area - a.area);
}

export interface FinderDetection {
  centers: [Point2, Point2, Point2, Point2];
  /** True when the corner assignment is geometrically consistent. */
  ordered: boolean;
}

/**
 * Locate the four finder squares.
 *
 * Finder squares sit outside the payload, so they are the four outermost dark
 * components, roughly 90 degrees apart around the frame centre. Ordering the
 * candidates by radius and enforcing angular separation rejects the large dark
 * payload blobs that dominate an area-sorted list while staying rotation
 * invariant. The 2x2 top-left marker is then the smallest of the four; the
 * others are read clockwise from the centroid, which works for any rotation.
 */
export function detectFinders(image: RgbImage, layout = createSpatialLayout()): FinderDetection | null {
  const cell = layout.cellPixels;
  // The 2x2 top-left finder is the smallest marker; accept components well
  // below its nominal area so strongly scaled-down captures still work.
  const minArea = Math.max(16, Math.round((2 * cell) * (2 * cell) * 0.12));
  const components = findDarkComponents(image, {
    minArea,
    maxArea: (image.width * image.height) / 2,
  });
  if (components.length < 4) return null;

  // Frame centre, weighted by component area.
  let weight = 0;
  let centerX = 0;
  let centerY = 0;
  for (const component of components) {
    weight += component.area;
    centerX += component.cx * component.area;
    centerY += component.cy * component.area;
  }
  if (weight === 0) return null;
  centerX /= weight;
  centerY /= weight;

  const scored = components
    .map((component) => {
      const dx = component.cx - centerX;
      const dy = component.cy - centerY;
      return { component, angle: Math.atan2(dy, dx), radius: Math.hypot(dx, dy) };
    })
    .sort((a, b) => b.radius - a.radius);

  const chosen: Component[] = [];
  const minAngleGap = Math.PI / 3;
  for (const candidate of scored) {
    if (chosen.length === 4) break;
    let separated = true;
    for (const picked of chosen) {
      const pickedAngle = Math.atan2(picked.cy - centerY, picked.cx - centerX);
      let difference = Math.abs(candidate.angle - pickedAngle);
      if (difference > Math.PI) difference = 2 * Math.PI - difference;
      if (difference < minAngleGap) {
        separated = false;
        break;
      }
    }
    if (separated) chosen.push(candidate.component);
  }
  if (chosen.length < 4) return null;

  // The three 3x3 markers share an area; the 2x2 marker is ~4/9 of it.
  // A payload blob that slipped past the angular test breaks this ratio.
  let largest = 0;
  let smallest = Infinity;
  for (const component of chosen) {
    largest = Math.max(largest, component.area);
    smallest = Math.min(smallest, component.area);
  }
  if (largest === 0 || smallest < largest * 0.18 || smallest > largest * 1.3) {
    return null;
  }

  // The top-left finder is the 2x2 cell marker, so it has the smallest area.
  let topLeftIndex = 0;
  for (let i = 1; i < chosen.length; i++) {
    if (chosen[i].area < chosen[topLeftIndex].area) topLeftIndex = i;
  }

  // Sort all four around the centroid (clockwise in y-down screen space) and
  // rotate so the top-left marker is first: TL, TR, BR, BL.
  const ordered = [...chosen].sort(
    (a, b) =>
      Math.atan2(a.cy - centerY, a.cx - centerX) -
      Math.atan2(b.cy - centerY, b.cx - centerX)
  );
  const start = ordered.indexOf(chosen[topLeftIndex]);
  const rerolled = [...ordered.slice(start), ...ordered.slice(0, start)];

  // Geometric sanity: the four markers must form a convex quad with roughly
  // quadrant spacing. This rejects most payload-only or noise frames early.
  const angles = rerolled.map((component) =>
    Math.atan2(component.cy - centerY, component.cx - centerX)
  );
  for (let i = 0; i < 4; i++) {
    let gap = angles[(i + 1) % 4] - angles[i];
    if (gap < 0) gap += 2 * Math.PI;
    if (gap < Math.PI / 3.6 || gap > Math.PI / 1.38) return null;
  }
  let orientation = 0;
  for (let i = 0; i < 4; i++) {
    const a = rerolled[i];
    const b = rerolled[(i + 1) % 4];
    const c = rerolled[(i + 2) % 4];
    const cross = (b.cx - a.cx) * (c.cy - a.cy) - (b.cy - a.cy) * (c.cx - a.cx);
    if (cross === 0) return null;
    const sign = cross > 0 ? 1 : -1;
    if (orientation === 0) orientation = sign;
    else if (sign !== orientation) return null;
  }

  const centers: [Point2, Point2, Point2, Point2] = [
    { x: rerolled[0].cx, y: rerolled[0].cy },
    { x: rerolled[1].cx, y: rerolled[1].cy },
    { x: rerolled[2].cx, y: rerolled[2].cy },
    { x: rerolled[3].cx, y: rerolled[3].cy },
  ];
  const isOrdered = isClockwise(centers[0], centers[1], centers[2], centers[3]);
  return { centers, ordered: isOrdered };
}

function isClockwise(a: Point2, b: Point2, c: Point2, d: Point2): boolean {
  const cross = (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x);
  const cross2 = (c.x - a.x) * (d.y - a.y) - (c.y - a.y) * (d.x - a.x);
  return cross > 0 && cross2 > 0;
}

/** Two candidate orderings: as detected, and with TR/BL swapped. */
export function finderOrderings(detection: FinderDetection): [
  Point2,
  Point2,
  Point2,
  Point2,
][] {
  const [tl, tr, br, bl] = detection.centers;
  return [
    [tl, tr, br, bl],
    [tl, bl, br, tr],
  ];
}

/** Payload pixel quad implied by an ordered set of finder centres. */
export function payloadQuadFromFinders(
  finders: [Point2, Point2, Point2, Point2],
  layout = createSpatialLayout()
): [Point2, Point2, Point2, Point2] {
  const H = computeHomography(layout.finderPlaneCenters, finders);
  return layout.planeCorners.map((p) => applyHomography(H, p)) as [
    Point2,
    Point2,
    Point2,
    Point2,
  ];
}

/** Classic Otsu threshold over 8-bit samples. */
export function otsuThreshold(values: ArrayLike<number>): number {
  const histogram = new Float64Array(256);
  for (let i = 0; i < values.length; i++) {
    const value = Math.max(0, Math.min(255, Math.round(values[i])));
    histogram[value]++;
  }
  const total = values.length;
  let sum = 0;
  for (let i = 0; i < 256; i++) sum += i * histogram[i];
  let sumBackground = 0;
  let weightBackground = 0;
  let bestVariance = -1;
  let threshold = 127;
  for (let t = 0; t < 256; t++) {
    weightBackground += histogram[t];
    if (weightBackground === 0) continue;
    const weightForeground = total - weightBackground;
    if (weightForeground === 0) break;
    sumBackground += t * histogram[t];
    const meanBackground = sumBackground / weightBackground;
    const meanForeground = (sum - sumBackground) / weightForeground;
    const variance =
      weightBackground * weightForeground * (meanBackground - meanForeground) ** 2;
    if (variance > bestVariance) {
      bestVariance = variance;
      threshold = t;
    }
  }
  return threshold;
}

/**
 * Otsu split followed by refinement to the midpoint of the two cluster means.
 * The raw Otsu level sits on the last "dark" bin; the midpoint gives a much
 * better confidence measure for LLR weighting.
 */
export function twoClusterThreshold(values: ArrayLike<number>): number {
  const otsu = otsuThreshold(values);
  let lowSum = 0;
  let lowCount = 0;
  let highSum = 0;
  let highCount = 0;
  for (let i = 0; i < values.length; i++) {
    if (values[i] <= otsu) {
      lowSum += values[i];
      lowCount++;
    } else {
      highSum += values[i];
      highCount++;
    }
  }
  if (lowCount === 0 || highCount === 0) return otsu;
  return (lowSum / lowCount + highSum / highCount) / 2;
}

export interface SampledSpatialFrame {
  bits: Uint8Array;
  bytes: Uint8Array;
  /** Per-bit probability that the sampled bit is wrong. */
  errorProbabilities: Float32Array;
  thresholds: [number, number, number];
  payloadQuad: [Point2, Point2, Point2, Point2];
}

/**
 * Sample a payload quad. The quad must be TL/TR/BR/BL of the 32x32 payload
 * (not the finder squares). Per-channel thresholds are estimated from all
 * cells, which absorbs exposure and white-balance drift.
 */
export function sampleSpatialFrame(
  image: RgbImage,
  payloadQuad: [Point2, Point2, Point2, Point2],
  layout = createSpatialLayout()
): SampledSpatialFrame {
  const H = computeHomography(layout.planeCorners, payloadQuad);
  const samples = new Float32Array(SPATIAL_CODEWORD_BITS);
  const cellSamples: [number, number, number][] = [];

  for (let y = 0; y < layout.gridSize; y++) {
    for (let x = 0; x < layout.gridSize; x++) {
      const mapped = applyHomography(H, { x: x + 0.5, y: y + 0.5 });
      const rgb = sampleBilinear(image, mapped.x, mapped.y);
      cellSamples.push(rgb);
      for (let channel = 0; channel < 3; channel++) {
        samples[cellBitIndex(x, y, channel, layout.gridSize)] = rgb[channel];
      }
    }
  }

  const thresholds: [number, number, number] = [0, 0, 0];
  for (let channel = 0; channel < 3; channel++) {
    const values = new Float32Array(cellSamples.length);
    for (let i = 0; i < cellSamples.length; i++) values[i] = cellSamples[i][channel];
    thresholds[channel] = twoClusterThreshold(values);
  }

  const bits = new Uint8Array(SPATIAL_CODEWORD_BITS);
  const errorProbabilities = new Float32Array(SPATIAL_CODEWORD_BITS);
  for (let y = 0; y < layout.gridSize; y++) {
    for (let x = 0; x < layout.gridSize; x++) {
      const rgb = cellSamples[y * layout.gridSize + x];
      for (let channel = 0; channel < 3; channel++) {
        const index = cellBitIndex(x, y, channel, layout.gridSize);
        const value = rgb[channel];
        const threshold = thresholds[channel];
        bits[index] = value >= threshold ? 1 : 0;
        const distance = Math.abs(value - threshold);
        errorProbabilities[index] = Math.min(0.45, Math.max(0.001, 0.5 * Math.exp(-distance / 24)));
      }
    }
  }

  return {
    bits,
    bytes: bitsToBytes(bits),
    errorProbabilities,
    thresholds,
    payloadQuad,
  };
}

export interface SpatialDecodeResult extends SampledSpatialFrame {
  finders: [Point2, Point2, Point2, Point2];
  planeToImage: Mat3;
}

/**
 * Full optical decode: detect finders, try both possible corner windings,
 * sample the payload and let the caller validate (CRC/LDPC/frame parsing).
 */
export function decodeSpatialFrame(
  image: RgbImage,
  validate: (sampled: SampledSpatialFrame) => boolean,
  layout = createSpatialLayout()
): SpatialDecodeResult | null {
  const detection = detectFinders(image, layout);
  if (!detection) return null;
  for (const finders of finderOrderings(detection)) {
    const quad = payloadQuadFromFinders(finders, layout);
    const sampled = sampleSpatialFrame(image, quad, layout);
    if (validate(sampled)) {
      return {
        ...sampled,
        finders,
        planeToImage: computeHomography(layout.planeCorners, quad),
      };
    }
  }
  return null;
}

/** Rectify a captured frame to an upright payload-only image. */
export function rectifySpatialFrame(
  image: RgbImage,
  payloadQuad: [Point2, Point2, Point2, Point2],
  layout = createSpatialLayout()
): RgbImage {
  const size = layout.gridSize * layout.cellPixels;
  // Output pixels are payload pixels: output (0..size) corresponds to payload
  // plane coordinates scaled by `cellPixels`.
  const outputCorners = layout.planeCorners.map((point) => ({
    x: point.x * layout.cellPixels,
    y: point.y * layout.cellPixels,
  }));
  const H = computeHomography(payloadQuad, outputCorners);
  return warpPerspective(image, H, size, size);
}

/** Convenience: render a frame and apply an arbitrary output homography. */
export function renderAndWarp(
  codewordBits: Uint8Array,
  outputHomography: Mat3,
  options: RenderOptions & { outWidth?: number; outHeight?: number } = {}
): RgbImage {
  const rendered = renderSpatialFrame(codewordBits, options);
  const outWidth = options.outWidth ?? rendered.layout.width;
  const outHeight = options.outHeight ?? rendered.layout.height;
  return warpPerspective(rendered.image, outputHomography, outWidth, outHeight);
}
