/**
 * EntropyCryptoPool — non-camera entropy source (desktop / Node target).
 *
 * The desktop counterpart to the mobile dual-photo photonic digest. Instead of
 * a camera sensor, it condenses a live pool of machine + human entropy into a
 * 256-bit digest in the same 64-hex format:
 *
 *   - Timer jitter: monotonic vs wall-clock drift, event-loop scheduling lag
 *   - Human interaction: pointer coordinates, interaction timing, key timing
 *     (timing only — never key content)
 *   - Machine state: window/screen geometry, device pixel ratio
 *   - CSPRNG contribution: Node crypto.randomBytes or crypto.getRandomValues
 *
 * No external dependencies. Condensed with the built-in SHA-256.
 *
 * Experimental post-quantum key-material layer on top of standard
 * cryptography — it does not replace it (see README caveats).
 */

import { sha256Hex } from './photonicQuantumAnalyzer';

function now(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now();
}

interface PoolSample {
  n: number;
  t: number;
  w: number[];
}

export class EntropyCryptoPool {
  private samples: PoolSample[] = [];
  private counter = 0;
  private started = false;
  private lastWall = 0;
  private lastMono = 0;
  private lastTimeoutMark = 0;
  private readonly maxSamples = 512;

  stats = { samples: 0, sources: 0, lastDigestAt: 0 };

  /** Node.js clock access (Electron / non-browser target), optional */
  private nodeCrypto(): any | null {
    try {
      const anyGlobal = globalThis as any;
      if (typeof window !== 'undefined' && (window as any).require) {
        return (window as any).require('crypto');
      }
      if (typeof anyGlobal.require === 'function') {
        return anyGlobal.require('crypto');
      }
    } catch {}
    return null;
  }

  /** CSPRNG contribution: Node crypto when available, else Web Crypto */
  private csprngWords(count = 4): number[] {
    try {
      const bytes = new Uint8Array(count * 4);
      const node = this.nodeCrypto();
      if (node?.randomBytes) {
        bytes.set(new Uint8Array(node.randomBytes(count * 4)));
      } else if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        crypto.getRandomValues(bytes);
      } else {
        return [];
      }
      const view = new DataView(bytes.buffer);
      const words: number[] = [];
      for (let i = 0; i < count; i++) words.push(view.getUint32(i * 4, false));
      return words;
    } catch {
      return [];
    }
  }

  start(): void {
    if (this.started) return;
    this.started = true;

    const push = (words: number[]) => {
      this.counter++;
      this.samples.push({ n: this.counter, t: Date.now(), w: words.slice(0, 4).map((x) => x >>> 0) });
      if (this.samples.length > this.maxSamples) {
        this.samples.splice(0, this.samples.length - this.maxSamples);
      }
      this.stats.samples = this.samples.length;
      this.stats.sources = this.countSources();
    };

    // Timer jitter (browser or Node via setTimeout)
    setInterval(() => {
      const mono = now();
      const wall = Date.now();
      if (this.lastWall && this.lastMono) {
        const wallDrift = wall - this.lastWall;
        const monoDrift = Math.round(mono - this.lastMono);
        const skew = (wallDrift - monoDrift) >>> 0;
        push([skew, Math.floor(mono * 1000) >>> 0, (monoDrift << 16) ^ (wall & 0xffff)]);
      }
      this.lastWall = wall;
      this.lastMono = mono;
    }, 50);

    // Event-loop lag
    const loopLag = () => {
      const mark = now();
      setTimeout(() => {
        const lag = Math.round(now() - mark - 20) >>> 0;
        if (this.lastTimeoutMark) push([lag, Math.floor(now()) >>> 0]);
        this.lastTimeoutMark = mark;
        loopLag();
      }, 20);
    };
    loopLag();

    // Human interaction entropy (browser)
    if (typeof window !== 'undefined') {
      const pointer = (e: PointerEvent | MouseEvent) => {
        push([
          (e.clientX * 31 + e.clientY * 17) >>> 0,
          e.timeStamp >>> 0,
          (e.screenX * 13 + e.screenY * 7) >>> 0,
        ]);
      };
      const keyTiming = (e: KeyboardEvent) => {
        push([e.timeStamp >>> 0, (e.timeStamp * 7919) >>> 0]);
      };
      window.addEventListener('pointermove', pointer, { passive: true });
      window.addEventListener('keydown', keyTiming, { passive: true });

      const machineState = () => {
        push([
          (window.innerWidth * 6151 + window.innerHeight * 2741) >>> 0,
          (window.screen.width * 3571 + window.screen.height * 4271) >>> 0,
          Math.floor((window.devicePixelRatio || 1) * 104729) >>> 0,
        ]);
      };
      machineState();
      window.addEventListener('resize', machineState, { passive: true });
    } else {
      // Node machine state: memory + uptime jitter (indirect access, browser-safe types)
      const anyGlobal = globalThis as any;
      const nodeState = () => {
        const mem = typeof anyGlobal.process?.memoryUsage === 'function' ? anyGlobal.process.memoryUsage() : null;
        push([
          (mem ? mem.rss >>> 0 : 0) || Date.now() >>> 0,
          Math.floor(now() * 1000) >>> 0,
          ...this.csprngWords(2),
        ]);
      };
      nodeState();
      setInterval(nodeState, 250);
    }
  }

  private countSources(): number {
    return 4; // timer jitter + event-loop lag + interaction/machine state + CSPRNG
  }

  /**
   * Condenses the pool into a 256-bit hex digest (64 chars) — same format as
   * the mobile photonic dual-photo digest. Tops up with jitter + CSPRNG so
   * acceptance never blocks on user interaction.
   */
  condense(minSamples = 12): string | null {
    this.start();
    let guard = 0;
    while (this.samples.length < minSamples && guard < 64) {
      guard++;
      this.counter++;
      this.samples.push({
        n: this.counter,
        t: Date.now(),
        w: [Math.floor(now() * 1000) >>> 0, (Date.now() * 2654435761) >>> 0, ...this.csprngWords(2)],
      });
    }
    this.stats.samples = this.samples.length;

    const serialized: number[] = [];
    for (const s of this.samples) {
      serialized.push(s.n >>> 0, s.t >>> 0, ...s.w);
    }
    serialized.push(...this.csprngWords(8));

    const byteLen = serialized.length * 4;
    const bytes = new Uint8Array(byteLen);
    const view = new DataView(bytes.buffer);
    serialized.forEach((w, i) => view.setUint32(i * 4, w >>> 0, false));

    this.stats.lastDigestAt = Date.now();
    return sha256Hex(bytes);
  }

  condenseWithStats(minSamples = 12): { digest: string; samples: number; sources: number } | null {
    const digest = this.condense(minSamples);
    if (!digest) return null;
    return { digest, samples: this.stats.samples, sources: this.stats.sources };
  }
}

/** Shared singleton pool for the app lifetime. */
export const entropyCryptoPool = new EntropyCryptoPool();
