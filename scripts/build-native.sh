#!/usr/bin/env bash
# Build the zero-dependency Rust core and its wasm32 artifact.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/native"

if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi

echo "==> Rust core tests"
cargo test --release -p clasp_photon_core

echo "==> Native release build (rlib + CLI)"
cargo build --release -p clasp_photon_core

if rustup target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
  echo "==> wasm32 release build"
  cargo build --release --target wasm32-unknown-unknown -p clasp_photon_wasm
  mkdir -p "$ROOT/dist"
  cp "target/wasm32-unknown-unknown/release/clasp_photon_wasm.wasm" "$ROOT/dist/clasp_photon_wasm.wasm"
  echo "    wrote dist/clasp_photon_wasm.wasm"
else
  echo "!! wasm32-unknown-unknown target not installed; skipping wasm build"
  echo "   install with: rustup target add wasm32-unknown-unknown"
fi

echo "==> Native build complete"
