#!/usr/bin/env bash
set -euo pipefail

RUNS="${FUZZ_RUNS:-1000000}"
SANITIZER="${FUZZ_SANITIZER:-none}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FUZZ_DIR="$REPO_ROOT/fuzz"
ARTIFACTS_DIR="$FUZZ_DIR/artifacts"
CORPUS_DIR="$FUZZ_DIR/corpus"
SEEDS_DIR="$FUZZ_DIR/seeds"

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
    exec wsl.exe -u root -e bash -lc "export HOME=/root; if [ -f \"\$HOME/.cargo/env\" ]; then . \"\$HOME/.cargo/env\"; fi; cd '$wsl_root' && FUZZ_RUNS='$RUNS' FUZZ_SANITIZER='$SANITIZER' ./scripts/fuzz-ci.sh"
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

echo "Running fuzz targets with $RUNS iterations each (sanitizer=$SANITIZER)."

run_target() {
  local target="$1"
  local corpus="$CORPUS_DIR/$target"
  local seeds="$SEEDS_DIR/$target"
  local artifacts="$ARTIFACTS_DIR/$target"

  mkdir -p "$corpus" "$artifacts"

  if [[ -d "$seeds" ]] && [[ -n "$(find "$seeds" -type f -print -quit)" ]]; then
    echo "Merging seeds into corpus for target: $target"
    cargo fuzz run -O -s "$SANITIZER" "$target" "$corpus" "$seeds" -- -merge=1 >/dev/null
  fi

  echo "Fuzzing target: $target"
  cargo fuzz run -O -s "$SANITIZER" "$target" "$corpus" -- -runs="$RUNS" -artifact_prefix="$artifacts/"
}

pushd "$FUZZ_DIR" > /dev/null
run_target hash_parser
run_target flatbuf_payloads
popd > /dev/null
