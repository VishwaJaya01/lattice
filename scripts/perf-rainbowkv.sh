#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${LATTICE_PERF_OUT_DIR:-$ROOT/docs/perf-runs}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FILE="$OUT_DIR/rainbowkv-lookup-$STAMP.txt"

mkdir -p "$OUT_DIR"
cd "$ROOT"

echo "running RainbowKV benchmark..."
cargo bench -p rainbowkv --bench lookup | tee "$OUT_FILE"

echo "saved benchmark output to: $OUT_FILE"
