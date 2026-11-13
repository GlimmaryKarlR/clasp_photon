//! Command-line harness for the native core.
//!
//! Used by scripts/crosscheck-native.mjs to prove byte-for-byte agreement with
//! the TypeScript reference implementation, and by CI as a smoke test.
//!
//! Usage:
//!   photon_cli keygen <seed-hex-32>
//!   photon_cli encaps <pk-hex> <randomness-hex-32>
//!   photon_cli decaps <sk-hex> <ct-hex>
//!   photon_cli bench [iterations]

use std::env;
use std::process::exit;
use std::time::Instant;

use clasp_photon_core::mlkem;

fn parse_hex(value: &str) -> Vec<u8> {
    let clean = value.trim();
    if clean.len() % 2 != 0 {
        eprintln!("hex length must be even");
        exit(2);
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    let bytes = clean.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).unwrap();
        match u8::from_str_radix(pair, 16) {
            Ok(byte) => out.push(byte),
            Err(_) => {
                eprintln!("invalid hex");
                exit(2);
            }
        }
        i += 2;
    }
    out
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn fixed<const L: usize>(hex: &str, name: &str) -> [u8; L] {
    let bytes = parse_hex(hex);
    if bytes.len() != L {
        eprintln!("{} must be {} bytes, got {}", name, L, bytes.len());
        exit(2);
    }
    let mut out = [0u8; L];
    out.copy_from_slice(&bytes);
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: photon_cli <keygen|encaps|decaps|bench> ...");
        exit(2);
    }

    match args[1].as_str() {
        "keygen" => {
            if args.len() < 3 {
                eprintln!("usage: photon_cli keygen <seed-hex-32>");
                exit(2);
            }
            let seed = fixed::<32>(&args[2], "seed");
            let mut pk = [0u8; mlkem::PUBLIC_KEY_BYTES];
            let mut sk = [0u8; mlkem::SECRET_KEY_BYTES];
            mlkem::keygen_deterministic(&seed, &mut pk, &mut sk);
            println!("pk={}", to_hex(&pk));
            println!("sk={}", to_hex(&sk));
        }
        "encaps" => {
            if args.len() < 4 {
                eprintln!("usage: photon_cli encaps <pk-hex> <randomness-hex-32>");
                exit(2);
            }
            let pk = fixed::<{ mlkem::PUBLIC_KEY_BYTES }>(&args[2], "public key");
            let randomness = fixed::<32>(&args[3], "randomness");
            let mut ct = [0u8; mlkem::CIPHERTEXT_BYTES];
            let mut ss = [0u8; mlkem::SHARED_SECRET_BYTES];
            mlkem::encaps(&pk, &randomness, &mut ct, &mut ss);
            println!("ct={}", to_hex(&ct));
            println!("ss={}", to_hex(&ss));
        }
        "decaps" => {
            if args.len() < 4 {
                eprintln!("usage: photon_cli decaps <sk-hex> <ct-hex>");
                exit(2);
            }
            let sk = fixed::<{ mlkem::SECRET_KEY_BYTES }>(&args[2], "secret key");
            let ct = fixed::<{ mlkem::CIPHERTEXT_BYTES }>(&args[3], "ciphertext");
            let mut ss = [0u8; mlkem::SHARED_SECRET_BYTES];
            mlkem::decaps(&sk, &ct, &mut ss);
            println!("ss={}", to_hex(&ss));
        }
        "bench" => {
            let iterations: u32 = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(10);
            let seed = [7u8; 32];
            let mut pk = [0u8; mlkem::PUBLIC_KEY_BYTES];
            let mut sk = [0u8; mlkem::SECRET_KEY_BYTES];
            let start = Instant::now();
            mlkem::keygen_deterministic(&seed, &mut pk, &mut sk);
            let keygen = start.elapsed();

            let mut ct = [0u8; mlkem::CIPHERTEXT_BYTES];
            let mut ss = [0u8; mlkem::SHARED_SECRET_BYTES];
            let start = Instant::now();
            for i in 0..iterations {
                let mut randomness = [0u8; 32];
                randomness[0] = i as u8;
                mlkem::encaps(&pk, &randomness, &mut ct, &mut ss);
            }
            let encaps = start.elapsed() / iterations;

            let start = Instant::now();
            for _ in 0..iterations {
                mlkem::decaps(&sk, &ct, &mut ss);
            }
            let decaps = start.elapsed() / iterations;

            println!("keygen_us={}", keygen.as_micros());
            println!("encaps_us={}", encaps.as_micros());
            println!("decaps_us={}", decaps.as_micros());
        }
        other => {
            eprintln!("unknown command: {}", other);
            exit(2);
        }
    }
}
