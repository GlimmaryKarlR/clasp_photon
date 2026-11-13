/**
 * Base85 for SMS / low-bandwidth carriers.
 *
 * Four bytes become five printable characters (25% overhead, better than
 * Base64). The default alphabet is Adobe Ascii85; `SMS_BASE85_ALPHABET`
 * excludes quotes and backslashes so frames can be embedded in plain text
 * messages without escaping.
 */

export const ASCII85_ALPHABET =
  '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu';

export const SMS_BASE85_ALPHABET =
  '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+,-./:;<=>?@[]_';

if (ASCII85_ALPHABET.length !== 85) throw new Error('Ascii85 alphabet must contain 85 characters');
if (SMS_BASE85_ALPHABET.length !== 85) throw new Error('SMS Base85 alphabet must contain 85 characters');
if (new Set(ASCII85_ALPHABET).size !== 85) throw new Error('Ascii85 alphabet has duplicates');
if (new Set(SMS_BASE85_ALPHABET).size !== 85) throw new Error('SMS Base85 alphabet has duplicates');

export function base85Encode(bytes: Uint8Array, alphabet = ASCII85_ALPHABET): string {
  if (alphabet.length !== 85) throw new Error('alphabet must contain 85 characters');
  let out = '';
  for (let offset = 0; offset < bytes.length; offset += 4) {
    const remaining = Math.min(4, bytes.length - offset);
    let value = 0;
    for (let i = 0; i < 4; i++) {
      value = value * 256 + (i < remaining ? bytes[offset + i] : 0);
    }
    const digits = new Array<number>(5);
    for (let i = 4; i >= 0; i--) {
      digits[i] = value % 85;
      value = Math.floor(value / 85);
    }
    const count = remaining === 4 ? 5 : remaining + 1;
    for (let i = 0; i < count; i++) out += alphabet[digits[i]];
  }
  return out;
}

export function base85Decode(text: string, alphabet = ASCII85_ALPHABET): Uint8Array {
  if (alphabet.length !== 85) throw new Error('alphabet must contain 85 characters');
  const lookup = new Map<string, number>();
  for (let i = 0; i < alphabet.length; i++) lookup.set(alphabet[i], i);

  const values: number[] = [];
  for (const char of text) {
    if (/\s/.test(char)) continue;
    const value = lookup.get(char);
    if (value === undefined) throw new Error(`invalid Base85 character: ${JSON.stringify(char)}`);
    values.push(value);
  }
  const remainder = values.length % 5;
  if (remainder === 1) {
    throw new Error('Base85 final group is too short');
  }

  const out: number[] = [];
  const fullGroups = Math.floor(values.length / 5);
  for (let groupIndex = 0; groupIndex < fullGroups; groupIndex++) {
    let value = 0;
    for (let i = 0; i < 5; i++) value = value * 85 + values[groupIndex * 5 + i];
    if (value > 0xffffffff) throw new Error('Base85 group exceeds 32 bits');
    out.push(
      Math.floor(value / 0x1000000) & 0xff,
      Math.floor(value / 0x10000) & 0xff,
      Math.floor(value / 0x100) & 0xff,
      value & 0xff
    );
  }

  if (remainder > 0) {
    // Trailing partial group: the encoder emits `remaining + 1` characters
    // for `remaining` bytes and drops the low base85 digits. Recover the
    // original 32-bit value exactly by finding the unique zero-padded multiple
    // inside the interval the prefix selects.
    let prefix = 0;
    for (let i = 0; i < remainder; i++) {
      prefix = prefix * 85 + values[fullGroups * 5 + i];
    }
    const remaining = remainder - 1;
    const intervalLength = 85 ** (5 - remainder);
    const quantum = 256 ** (5 - remainder);
    const low = prefix * intervalLength;
    const value = Math.ceil(low / quantum) * quantum;
    if (value > 0xffffffff) throw new Error('Base85 group exceeds 32 bits');
    const group = [
      Math.floor(value / 0x1000000) & 0xff,
      Math.floor(value / 0x10000) & 0xff,
      Math.floor(value / 0x100) & 0xff,
      value & 0xff,
    ];
    out.push(...group.slice(0, remaining));
  }
  return Uint8Array.from(out);
}

/**
 * Base85 round-trips lose the exact number of padding bytes for partial final
 * groups. Callers that need framing should transmit a length prefix; this
 * helper decodes and then trims to `expectedLength`.
 */
export function base85DecodeExact(
  text: string,
  expectedLength: number,
  alphabet = ASCII85_ALPHABET
): Uint8Array {
  const decoded = base85Decode(text, alphabet);
  if (decoded.length < expectedLength) {
    throw new Error(`decoded ${decoded.length} bytes, expected ${expectedLength}`);
  }
  return decoded.subarray(0, expectedLength);
}
