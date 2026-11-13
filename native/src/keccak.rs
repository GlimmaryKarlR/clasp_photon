//! Keccak-f[1600], SHA3-256, SHA3-512, SHAKE128, SHAKE256.
//!
//! Zero dependencies, no_std. 64-bit lanes use native u64 arithmetic, which is
//! substantially faster than the BigInt reference implementation in TypeScript.

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

// Rotation offsets indexed [x][y].
const ROTATION: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

pub fn keccak_f1600(state: &mut [u64; 25]) {
    for round in 0..24 {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }

        // rho + pi
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] =
                    state[x + 5 * y].rotate_left(ROTATION[x][y]);
            }
        }

        // chi
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // iota
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

/// Generic Keccak sponge.
pub fn keccak_sponge(rate: usize, domain: u8, input: &[u8], out: &mut [u8]) {
    let mut state = [0u64; 25];
    let mut offset = 0usize;

    while input.len() - offset >= rate {
        for i in 0..rate {
            state[i / 8] ^= (input[offset + i] as u64) << (8 * (i % 8));
        }
        keccak_f1600(&mut state);
        offset += rate;
    }

    let remaining = input.len() - offset;
    for i in 0..remaining {
        state[i / 8] ^= (input[offset + i] as u64) << (8 * (i % 8));
    }
    state[remaining / 8] ^= (domain as u64) << (8 * (remaining % 8));
    state[(rate - 1) / 8] ^= 0x80u64 << (8 * ((rate - 1) % 8));
    keccak_f1600(&mut state);

    let mut produced = 0usize;
    while produced < out.len() {
        let take = core::cmp::min(rate, out.len() - produced);
        for i in 0..take {
            out[produced + i] = (state[i / 8] >> (8 * (i % 8))) as u8;
        }
        produced += take;
        if produced < out.len() {
            keccak_f1600(&mut state);
        }
    }
}

pub fn sha3_256(data: &[u8], out: &mut [u8; 32]) {
    keccak_sponge(136, 0x06, data, out);
}

pub fn sha3_512(data: &[u8], out: &mut [u8; 64]) {
    keccak_sponge(72, 0x06, data, out);
}

pub fn shake128(data: &[u8], out: &mut [u8]) {
    keccak_sponge(168, 0x1f, data, out);
}

pub fn shake256(data: &[u8], out: &mut [u8]) {
    keccak_sponge(136, 0x1f, data, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> std::string::String {
        let mut s = std::string::String::new();
        for b in bytes {
            s.push_str(&std::format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn sha3_256_vectors() {
        let mut out = [0u8; 32];
        sha3_256(b"", &mut out);
        assert_eq!(
            hex(&out),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        sha3_256(b"abc", &mut out);
        assert_eq!(
            hex(&out),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn shake_vectors() {
        let mut out = [0u8; 32];
        shake128(b"", &mut out);
        assert_eq!(
            hex(&out),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
        shake256(b"", &mut out);
        assert_eq!(
            hex(&out),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }
}
