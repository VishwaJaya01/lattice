#!/usr/bin/env bash
set -euo pipefail

RUNS="${FUZZ_RUNS:-1000000}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FUZZ_DIR="$REPO_ROOT/fuzz"

# cargo-fuzz + libFuzzer instrumentation is not reliable under native
# Windows/MSVC toolchains. If we are in Git Bash, prefer delegating to WSL.
uname_s="$(uname -s || true)"
if [[ "$uname_s" == MINGW* || "$uname_s" == MSYS* || "$uname_s" == CYGWIN* ]]; then
  if command -v wsl.exe >/dev/null 2>&1; then
    win_root="$(cd "$REPO_ROOT" && pwd -W)"
    drive="${win_root:0:1}"
    rest="${win_root:2}"
    drive="$(echo "$drive" | tr '[:upper:]' '[:lower:]')"
    rest="${rest//\\//}"
    wsl_root="/mnt/$drive$rest"

    echo "Detected Git Bash on Windows. Running fuzz in WSL for compatibility..."
    exec wsl.exe -u root -e bash -lc "export HOME=/root; if [ -f \"\$HOME/.cargo/env\" ]; then . \"\$HOME/.cargo/env\"; fi; cd '$wsl_root' && FUZZ_RUNS='$RUNS' ./scripts/fuzz-ci.sh"
  fi

  echo "Detected Git Bash on Windows without WSL available."
  echo "Install WSL2 and rerun this script, or run fuzzing on Linux/macOS."
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found in this shell."
  echo "Install Rust toolchain, then rerun:"
  echo "  curl https://sh.rustup.rs -sSf | sh -s -- -y"
  exit 1
fi

if ! cargo fuzz --help >/dev/null 2>&1; then
  echo "cargo-fuzz not found in this shell."
  echo "Install cargo-fuzz, then rerun:"
  echo "  cargo install cargo-fuzz --locked"
  exit 1
fi

echo "Running fuzz targets with $RUNS iterations each."

pushd "$FUZZ_DIR" > /dev/null
cargo fuzz run -O -s none hash_parser -- -runs="$RUNS"
cargo fuzz run -O -s none flatbuf_payloads -- -runs="$RUNS"
popd > /dev/null
