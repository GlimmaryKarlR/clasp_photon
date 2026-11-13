/**
 * CameraSensorController — Phase 2 sensor subsystem.
 *
 * Consumer camera pipelines auto-adjust exposure, gain and focus continuously.
 * For repeatable capture that is harmful: automatic gain changes brightness
 * mid-frame, autofocus hunts while the scene is being captured, and long
 * exposures smear rolling-shutter bands across the sensor.
 *
 * This module:
 *   1. Builds explicit manual constraints (ISO, exposure time, fixed focus,
 *      white balance, fixed frame rate) from `track.getCapabilities()`.
 *   2. Applies them and records what the sensor actually accepted.
 *   3. Captures two frames a fixed interval apart and reports the measured
 *      interval (the photonic co-signing path uses ~33 ms).
 *   4. Provides a display-refresh-locked `FrameClock` so captures are not
 *      torn across refresh boundaries.
 *
 * Browser-only APIs are touched lazily, so the pure helpers can be imported
 * and tested in Node.
 */

import { imageBitmapToGrayscaleArray } from '../photonicQuantumAnalyzer.js';

export interface RangeLike {
  max?: number;
  min?: number;
  step?: number;
}

export interface CameraCapabilitiesLike {
  exposureMode?: string[];
  exposureTime?: RangeLike;
  focusMode?: string[];
  focusDistance?: RangeLike;
  iso?: RangeLike;
  whiteBalanceMode?: string[];
  colorTemperature?: RangeLike;
  width?: RangeLike;
  height?: RangeLike;
  frameRate?: RangeLike;
}

export interface ManualCameraOptions {
  /** Target capture frame rate. Default 30. */
  targetFps?: number;
  /** Exposure time in 100 µs units (MediaTrackConstraint units). */
  exposureTime?: number;
  iso?: number;
  focusDistance?: number;
  colorTemperature?: number;
  width?: number;
  height?: number;
  /** Prefer the rear camera (default true). */
  rearCamera?: boolean;
}

export interface ConstraintPlan {
  videoConstraints: MediaTrackConstraints;
  applied: string[];
  skipped: string[];
}

function clampToRange(value: number, range?: RangeLike): number {
  if (!range) return value;
  const min = range.min ?? value;
  const max = range.max ?? value;
  return Math.min(max, Math.max(min, value));
}

/**
 * Build MediaTrackConstraints that force manual sensor control where the
 * platform reports support. Unsupported controls are skipped and reported
 * instead of triggering an OverconstrainedError.
 */
export function buildCameraConstraints(
  capabilities: CameraCapabilitiesLike,
  options: ManualCameraOptions = {}
): ConstraintPlan {
  const targetFps = options.targetFps ?? 30;
  const applied: string[] = [];
  const skipped: string[] = [];

  const constraints: MediaTrackConstraints = {
    width: { ideal: options.width ?? 1280 },
    height: { ideal: options.height ?? 720 },
    frameRate: { ideal: targetFps, max: targetFps },
  };
  applied.push('width', 'height', 'frameRate');

  if (options.rearCamera !== false && !capabilities.exposureMode) {
    // `facingMode` is not reported in getCapabilities on most browsers; it is
    // still accepted by getUserMedia. Keep it in the plan.
    (constraints as Record<string, unknown>).facingMode = { ideal: 'environment' };
    applied.push('facingMode');
  }

  const exposureModes = capabilities.exposureMode ?? [];
  if (exposureModes.includes('manual')) {
    (constraints as Record<string, unknown>).exposureMode = 'manual';
    applied.push('exposureMode=manual');
    if (capabilities.exposureTime) {
      const exposureTime = clampToRange(options.exposureTime ?? 20, capabilities.exposureTime);
      (constraints as Record<string, unknown>).exposureTime = exposureTime;
      applied.push('exposureTime');
    } else {
      skipped.push('exposureTime (range unknown)');
    }
  } else {
    skipped.push('exposureMode=manual (unsupported)');
  }

  if (capabilities.iso) {
    const iso = clampToRange(options.iso ?? 100, capabilities.iso);
    (constraints as Record<string, unknown>).iso = iso;
    applied.push('iso');
  } else {
    skipped.push('iso (unsupported)');
  }

  const focusModes = capabilities.focusMode ?? [];
  if (focusModes.includes('manual')) {
    (constraints as Record<string, unknown>).focusMode = 'manual';
    applied.push('focusMode=manual');
    if (capabilities.focusDistance) {
      const focusDistance = clampToRange(
        options.focusDistance ?? capabilities.focusDistance.min ?? 0,
        capabilities.focusDistance
      );
      (constraints as Record<string, unknown>).focusDistance = focusDistance;
      applied.push('focusDistance');
    } else {
      skipped.push('focusDistance (range unknown)');
    }
  } else {
    skipped.push('focusMode=manual (unsupported)');
  }

  const whiteBalanceModes = capabilities.whiteBalanceMode ?? [];
  if (whiteBalanceModes.includes('manual') && capabilities.colorTemperature) {
    (constraints as Record<string, unknown>).whiteBalanceMode = 'manual';
    (constraints as Record<string, unknown>).colorTemperature = clampToRange(
      options.colorTemperature ?? 5000,
      capabilities.colorTemperature
    );
    applied.push('whiteBalanceMode=manual', 'colorTemperature');
  } else {
    skipped.push('whiteBalanceMode=manual (unsupported)');
  }

  return { videoConstraints: constraints, applied, skipped };
}

export interface CapturePair {
  frames: [number[][], number[][]];
  requestedDeltaTMs: number;
  measuredDeltaTMs: number;
  settings: Record<string, unknown>;
  capabilities: CameraCapabilitiesLike;
  appliedConstraints: string[];
  skippedConstraints: string[];
}

/**
 * Owns a MediaStream and exposes manual, deterministic frame capture.
 */
export class CameraSensorController {
  private stream: MediaStream | null = null;
  private capture: { grabFrame(): Promise<ImageBitmap> } | null = null;
  private settings: Record<string, unknown> = {};
  private capabilities: CameraCapabilitiesLike = {};
  private applied: string[] = [];
  private skipped: string[] = [];
  private video: HTMLVideoElement | null = null;

  /** Whether the browser exposes the ImageCapture constructor. */
  static isSupported(): boolean {
    return (
      typeof navigator !== 'undefined' &&
      !!navigator.mediaDevices?.getUserMedia &&
      typeof (globalThis as Record<string, unknown>).ImageCapture === 'function'
    );
  }

  async open(
    video: HTMLVideoElement | null,
    options: ManualCameraOptions = {}
  ): Promise<void> {
    await this.close();
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: {
        facingMode: options.rearCamera === false ? 'user' : { ideal: 'environment' },
        width: { ideal: options.width ?? 1280 },
        height: { ideal: options.height ?? 720 },
      },
    });

    const track = stream.getVideoTracks()[0];
    if (!track) {
      stream.getTracks().forEach((t) => t.stop());
      throw new Error('camera stream has no video track');
    }

    this.stream = stream;
    const capabilities = (track.getCapabilities?.() ?? {}) as CameraCapabilitiesLike;
    this.capabilities = capabilities;
    const plan = buildCameraConstraints(capabilities, options);
    this.applied = plan.applied;
    this.skipped = plan.skipped;

    try {
      await track.applyConstraints(plan.videoConstraints);
    } catch {
      // Some browsers reject the full plan even when individual constraints
      // are supported. Retry with just the manual controls, then fall back.
      const minimal: MediaTrackConstraints = {};
      const source = plan.videoConstraints as Record<string, unknown>;
      for (const key of ['exposureMode', 'exposureTime', 'iso', 'focusMode', 'focusDistance']) {
        if (key in source) (minimal as Record<string, unknown>)[key] = source[key];
      }
      try {
        await track.applyConstraints(minimal);
      } catch {
        this.skipped.push('manual controls rejected by platform');
      }
    }

    this.settings = (track.getSettings?.() ?? {}) as Record<string, unknown>;

    if (video) {
      this.video = video;
      video.srcObject = stream;
      video.muted = true;
      video.playsInline = true;
      await video.play().catch(() => undefined);
    }

    const ImageCaptureCtor = (globalThis as Record<string, unknown>).ImageCapture as
      | (new (track: MediaStreamTrack) => { grabFrame(): Promise<ImageBitmap> })
      | undefined;
    if (ImageCaptureCtor) {
      this.capture = new ImageCaptureCtor(track);
    } else if (this.video) {
      // Fallback: draw the live video element into a canvas.
      this.capture = {
        grabFrame: async () => {
          const canvas = document.createElement('canvas');
          canvas.width = this.video!.videoWidth;
          canvas.height = this.video!.videoHeight;
          const ctx = canvas.getContext('2d');
          if (!ctx) throw new Error('canvas context unavailable');
          ctx.drawImage(this.video!, 0, 0);
          return createImageBitmap(canvas);
        },
      };
    } else {
      throw new Error('ImageCapture unavailable and no video element supplied');
    }
  }

  /** Capture two grayscale frames separated by `deltaTMs` (default 33 ms). */
  async capturePair(deltaTMs = 33): Promise<CapturePair> {
    if (!this.capture) throw new Error('camera not open');

    const start = performance.now();
    const frame1 = await this.capture.grabFrame();
    const afterFirst = performance.now();
    const remaining = deltaTMs - (afterFirst - start);
    if (remaining > 0) {
      await new Promise((resolve) => setTimeout(resolve, remaining));
    }
    const frame2 = await this.capture.grabFrame();
    const measured = performance.now() - start;

    const [arr1, arr2] = await Promise.all([
      imageBitmapToGrayscaleArray(frame1),
      imageBitmapToGrayscaleArray(frame2),
    ]);

    if (typeof frame1.close === 'function') frame1.close();
    if (typeof frame2.close === 'function') frame2.close();

    return {
      frames: [arr1, arr2],
      requestedDeltaTMs: deltaTMs,
      measuredDeltaTMs: measured,
      settings: { ...this.settings },
      capabilities: this.capabilities,
      appliedConstraints: [...this.applied],
      skippedConstraints: [...this.skipped],
    };
  }

  getSettings(): Record<string, unknown> {
    return { ...this.settings };
  }

  async close(): Promise<void> {
    this.stream?.getTracks().forEach((track) => track.stop());
    if (this.video) {
      this.video.srcObject = null;
      this.video = null;
    }
    this.stream = null;
    this.capture = null;
  }
}

export interface FrameStats {
  frames: number;
  durationMs: number;
  fps: number;
  meanIntervalMs: number;
  jitterMs: number;
}

/**
 * Display-refresh-locked render clock.
 *
 * Uses requestAnimationFrame where available (vsync-aligned) and a timer
 * fallback elsewhere. `tick(timestamp)` is public so tests can feed synthetic
 * timestamps without a DOM.
 */
export class FrameClock {
  private running = false;
  private handle: number | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private frameCount = 0;
  private startedAt = 0;
  private lastAt = 0;
  private intervals: number[] = [];
  private callback: ((timestamp: number, frameIndex: number) => void) | null = null;
  private readonly targetFps: number;

  constructor(targetFps = 30) {
    this.targetFps = targetFps;
  }

  start(callback: (timestamp: number, frameIndex: number) => void): void {
    if (this.running) return;
    this.running = true;
    this.callback = callback;
    this.frameCount = 0;
    this.intervals = [];
    const now = FrameClock.now();
    this.startedAt = now;
    this.lastAt = now;

    const raf = typeof requestAnimationFrame === 'function' ? requestAnimationFrame : null;
    if (raf) {
      const loop = (timestamp: number) => {
        if (!this.running) return;
        this.tick(timestamp);
        this.handle = raf(loop);
      };
      this.handle = raf(loop);
    } else {
      const interval = 1000 / this.targetFps;
      const loop = () => {
        if (!this.running) return;
        this.tick(FrameClock.now());
        this.timer = setTimeout(loop, interval);
      };
      this.timer = setTimeout(loop, interval);
    }
  }

  stop(): FrameStats {
    this.running = false;
    if (this.handle !== null && typeof cancelAnimationFrame === 'function') {
      cancelAnimationFrame(this.handle);
    }
    if (this.timer !== null) clearTimeout(this.timer);
    this.handle = null;
    this.timer = null;
    return this.stats();
  }

  /** Record a frame timestamp. Public for deterministic tests. */
  tick(timestamp: number): void {
    if (this.frameCount === 0) this.startedAt = timestamp;
    if (this.frameCount > 0) {
      this.intervals.push(timestamp - this.lastAt);
    }
    this.lastAt = timestamp;
    this.frameCount++;
    const index = this.frameCount - 1;
    const callback = this.callback;
    if (callback) callback(timestamp, index);
  }

  stats(): FrameStats {
    const durationMs = this.frameCount > 1 ? this.lastAt - this.startedAt : 0;
    const mean =
      this.intervals.length > 0
        ? this.intervals.reduce((sum, v) => sum + v, 0) / this.intervals.length
        : 0;
    const variance =
      this.intervals.length > 0
        ? this.intervals.reduce((sum, v) => sum + (v - mean) ** 2, 0) / this.intervals.length
        : 0;
    return {
      frames: this.frameCount,
      durationMs,
      fps: mean > 0 ? 1000 / mean : 0,
      meanIntervalMs: mean,
      jitterMs: Math.sqrt(variance),
    };
  }

  private static now(): number {
    return typeof performance !== 'undefined' ? performance.now() : Date.now();
  }
}
