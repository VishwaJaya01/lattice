#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d /tmp/lattice-smoke-XXXXXX)"
echo "smoke workdir: $WORKDIR"

on_err() {
  local code=$?
  echo "smoke failed (exit $code) at line ${BASH_LINENO[0]}: $BASH_COMMAND" >&2
  if [[ -n "${WORKDIR:-}" ]]; then
    [[ -f "$WORKDIR/worker.log" ]] && echo "worker log: $WORKDIR/worker.log" >&2
    [[ -f "$WORKDIR/orchestrator.log" ]] && echo "orchestrator log: $WORKDIR/orchestrator.log" >&2
  fi
  exit "$code"
}
trap on_err ERR

# Git Bash on Windows may not inherit Cargo/Go paths from PowerShell.
if [[ -n "${USERPROFILE:-}" ]]; then
  USERPROFILE_UNIX="$(cygpath -u "$USERPROFILE" 2>/dev/null || true)"
  if [[ -n "$USERPROFILE_UNIX" ]]; then
    PATH="$PATH:$USERPROFILE_UNIX/.cargo/bin:$USERPROFILE_UNIX/go/bin"
  fi
  if [[ -d "/c/Program Files/Go/bin" ]]; then
    PATH="$PATH:/c/Program Files/Go/bin"
  fi
fi

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd openssl
need_cmd cargo
need_cmd go

pick_python() {
  for cand in "${LATTICE_PYTHON:-}" python3 python; do
    [[ -z "$cand" ]] && continue
    if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "import sys" >/dev/null 2>&1; then
      echo "$cand"
      return 0
    fi
  done
  return 1
}

if ! PYTHON_BIN="$(pick_python)"; then
  echo "missing required command: python3 (or python)" >&2
  exit 1
fi
echo "python interpreter: $PYTHON_BIN"

# Git Bash/MSYS may rewrite "/CN=..." into a Windows path.
# Exclude only CN subject arguments, while keeping path conversion enabled.
openssl_req() {
  MSYS2_ARG_CONV_EXCL='/CN=' openssl req "$@"
}

cleanup() {
  if [[ -n "${WORKER_PID:-}" ]]; then
    kill "$WORKER_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${ORCH_PID:-}" ]]; then
    kill "$ORCH_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

CA_KEY="$WORKDIR/ca.key"
CA_CERT="$WORKDIR/ca.crt"

ORCH_KEY="$WORKDIR/orchestrator.key"
ORCH_CERT="$WORKDIR/orchestrator.crt"

WORKER_KEY="$WORKDIR/worker.key"
WORKER_CERT="$WORKDIR/worker.crt"

CLIENT_KEY="$WORKDIR/client.key"
CLIENT_CERT="$WORKDIR/client.crt"

echo "generating CA cert..."
openssl genrsa -out "$CA_KEY" 4096 >/dev/null
openssl_req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
  -subj "/CN=lattice-ca" -out "$CA_CERT" >/dev/null

create_cert() {
  local name="$1"
  local cn="$2"
  local key="$3"
  local csr="$4"
  local cert="$5"
  local ext="$6"

  openssl genrsa -out "$key" 2048 >/dev/null
  openssl_req -new -key "$key" -subj "/CN=$cn" -out "$csr" >/dev/null
  cat >"$ext" <<EXT
subjectAltName=DNS:$cn
EXT
  openssl x509 -req -in "$csr" -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -CAcreateserial -out "$cert" -days 365 -sha256 -extfile "$ext" >/dev/null
}

create_cert orchestrator lattice-orchestrator "$ORCH_KEY" "$WORKDIR/orch.csr" "$ORCH_CERT" "$WORKDIR/orch.ext"
create_cert worker lattice-worker "$WORKER_KEY" "$WORKDIR/worker.csr" "$WORKER_CERT" "$WORKDIR/worker.ext"
create_cert client lattice-client "$CLIENT_KEY" "$WORKDIR/client.csr" "$CLIENT_CERT" "$WORKDIR/client.ext"

TABLE="$WORKDIR/demo.lattice"
echo "generating demo table..."
"$PYTHON_BIN" "$ROOT/scripts/generate-demo-table.py" --output "$TABLE" --chain-len 100 --chain-count 5000

HASH_FILE="$WORKDIR/hashes.txt"
echo "generating test hash input..."
"$PYTHON_BIN" - <<'PY' >"$HASH_FILE"
import struct

CHARSET = b"abcdefghijklmnopqrstuvwxyz0123456789"
PASSWORD_LEN = 6
CHAIN_LEN = 100
START = 42
POS = 10


def md4_hash(message: bytes) -> bytes:
    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    def rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    bit_len = len(message) * 8
    padded = bytearray(message)
    padded.append(0x80)
    while (len(padded) % 64) != 56:
        padded.append(0)
    padded += struct.pack("<Q", bit_len)

    for chunk_start in range(0, len(padded), 64):
        chunk = padded[chunk_start : chunk_start + 64]
        x = list(struct.unpack("<16I", chunk))
        a, b, c, d = state

        a = rotl((a + f(b, c, d) + x[0]) & 0xffffffff, 3)
        d = rotl((d + f(a, b, c) + x[1]) & 0xffffffff, 7)
        c = rotl((c + f(d, a, b) + x[2]) & 0xffffffff, 11)
        b = rotl((b + f(c, d, a) + x[3]) & 0xffffffff, 19)
        a = rotl((a + f(b, c, d) + x[4]) & 0xffffffff, 3)
        d = rotl((d + f(a, b, c) + x[5]) & 0xffffffff, 7)
        c = rotl((c + f(d, a, b) + x[6]) & 0xffffffff, 11)
        b = rotl((b + f(c, d, a) + x[7]) & 0xffffffff, 19)
        a = rotl((a + f(b, c, d) + x[8]) & 0xffffffff, 3)
        d = rotl((d + f(a, b, c) + x[9]) & 0xffffffff, 7)
        c = rotl((c + f(d, a, b) + x[10]) & 0xffffffff, 11)
        b = rotl((b + f(c, d, a) + x[11]) & 0xffffffff, 19)
        a = rotl((a + f(b, c, d) + x[12]) & 0xffffffff, 3)
        d = rotl((d + f(a, b, c) + x[13]) & 0xffffffff, 7)
        c = rotl((c + f(d, a, b) + x[14]) & 0xffffffff, 11)
        b = rotl((b + f(c, d, a) + x[15]) & 0xffffffff, 19)

        a = rotl((a + g(b, c, d) + x[0] + 0x5a827999) & 0xffffffff, 3)
        d = rotl((d + g(a, b, c) + x[4] + 0x5a827999) & 0xffffffff, 5)
        c = rotl((c + g(d, a, b) + x[8] + 0x5a827999) & 0xffffffff, 9)
        b = rotl((b + g(c, d, a) + x[12] + 0x5a827999) & 0xffffffff, 13)
        a = rotl((a + g(b, c, d) + x[1] + 0x5a827999) & 0xffffffff, 3)
        d = rotl((d + g(a, b, c) + x[5] + 0x5a827999) & 0xffffffff, 5)
        c = rotl((c + g(d, a, b) + x[9] + 0x5a827999) & 0xffffffff, 9)
        b = rotl((b + g(c, d, a) + x[13] + 0x5a827999) & 0xffffffff, 13)
        a = rotl((a + g(b, c, d) + x[2] + 0x5a827999) & 0xffffffff, 3)
        d = rotl((d + g(a, b, c) + x[6] + 0x5a827999) & 0xffffffff, 5)
        c = rotl((c + g(d, a, b) + x[10] + 0x5a827999) & 0xffffffff, 9)
        b = rotl((b + g(c, d, a) + x[14] + 0x5a827999) & 0xffffffff, 13)
        a = rotl((a + g(b, c, d) + x[3] + 0x5a827999) & 0xffffffff, 3)
        d = rotl((d + g(a, b, c) + x[7] + 0x5a827999) & 0xffffffff, 5)
        c = rotl((c + g(d, a, b) + x[11] + 0x5a827999) & 0xffffffff, 9)
        b = rotl((b + g(c, d, a) + x[15] + 0x5a827999) & 0xffffffff, 13)

        a = rotl((a + h(b, c, d) + x[0] + 0x6ed9eba1) & 0xffffffff, 3)
        d = rotl((d + h(a, b, c) + x[8] + 0x6ed9eba1) & 0xffffffff, 9)
        c = rotl((c + h(d, a, b) + x[4] + 0x6ed9eba1) & 0xffffffff, 11)
        b = rotl((b + h(c, d, a) + x[12] + 0x6ed9eba1) & 0xffffffff, 15)
        a = rotl((a + h(b, c, d) + x[2] + 0x6ed9eba1) & 0xffffffff, 3)
        d = rotl((d + h(a, b, c) + x[10] + 0x6ed9eba1) & 0xffffffff, 9)
        c = rotl((c + h(d, a, b) + x[6] + 0x6ed9eba1) & 0xffffffff, 11)
        b = rotl((b + h(c, d, a) + x[14] + 0x6ed9eba1) & 0xffffffff, 15)
        a = rotl((a + h(b, c, d) + x[1] + 0x6ed9eba1) & 0xffffffff, 3)
        d = rotl((d + h(a, b, c) + x[9] + 0x6ed9eba1) & 0xffffffff, 9)
        c = rotl((c + h(d, a, b) + x[5] + 0x6ed9eba1) & 0xffffffff, 11)
        b = rotl((b + h(c, d, a) + x[13] + 0x6ed9eba1) & 0xffffffff, 15)
        a = rotl((a + h(b, c, d) + x[3] + 0x6ed9eba1) & 0xffffffff, 3)
        d = rotl((d + h(a, b, c) + x[11] + 0x6ed9eba1) & 0xffffffff, 9)
        c = rotl((c + h(d, a, b) + x[7] + 0x6ed9eba1) & 0xffffffff, 11)
        b = rotl((b + h(c, d, a) + x[15] + 0x6ed9eba1) & 0xffffffff, 15)

        state[0] = (state[0] + a) & 0xffffffff
        state[1] = (state[1] + b) & 0xffffffff
        state[2] = (state[2] + c) & 0xffffffff
        state[3] = (state[3] + d) & 0xffffffff

    return struct.pack("<4I", *state)


def ntlm_hash(pw_bytes: bytes) -> bytes:
    utf16 = bytearray()
    for b in pw_bytes:
        utf16.append(b)
        utf16.append(0)
    return md4_hash(bytes(utf16))


def decode_candidate(value: int) -> bytes:
    out = bytearray(PASSWORD_LEN)
    base = len(CHARSET)
    for i in range(PASSWORD_LEN):
        out[i] = CHARSET[value % base]
        value //= base
    return bytes(out)


def reduce_hash(hash_bytes: bytes, step: int, space: int) -> int:
    x = int.from_bytes(hash_bytes, "little")
    x = (x + (step * 0x9E3779B97F4A7C15)) & ((1 << 128) - 1)
    return x % space


space = len(CHARSET) ** PASSWORD_LEN
candidate = START
hash_bytes = b"\x00" * 16
for step in range(CHAIN_LEN):
    pw = decode_candidate(candidate)
    hash_bytes = ntlm_hash(pw)
    if step == POS:
        print(hash_bytes.hex())
        break
    candidate = reduce_hash(hash_bytes, step, space)
PY

if [[ "${LATTICE_SKIP_BUILD:-}" != "1" ]]; then
  echo "building worker, client, and orchestrator binaries..."
  cargo build -p lattice-worker -p flashaudit
  echo "building orchestrator (go modules may download on first run)..."
  if [[ "${LATTICE_SMOKE_FRESH_GO_CACHE:-0}" == "1" ]]; then
    GOTOOLCHAIN=local GOPATH="$WORKDIR/go" GOMODCACHE="$WORKDIR/go/pkg/mod" GOCACHE="$WORKDIR/go/cache" \
      go build -o "$WORKDIR/lattice-orchestrator" ./cmd/lattice-orchestrator
  else
    GOTOOLCHAIN=local go build -o "$WORKDIR/lattice-orchestrator" ./cmd/lattice-orchestrator
  fi
fi

WORKER_BIN="$ROOT/target/debug/lattice-worker"
FLASH_BIN="$ROOT/target/debug/flashaudit"
ORCH_BIN="$WORKDIR/lattice-orchestrator"

echo "starting worker..."
"$WORKER_BIN" \
  --addr 127.0.0.1:50052 \
  --node-id worker-1 \
  --metrics-addr 127.0.0.1:2113 \
  --table "$TABLE" \
  --tls-cert "$WORKER_CERT" \
  --tls-key "$WORKER_KEY" \
  --tls-client-ca "$CA_CERT" \
  >"$WORKDIR/worker.log" 2>&1 &
WORKER_PID=$!
sleep 1
if ! kill -0 "$WORKER_PID" >/dev/null 2>&1; then
  echo "worker exited early; showing log:" >&2
  cat "$WORKDIR/worker.log" >&2 || true
  exit 1
fi

echo "starting orchestrator..."
"$ORCH_BIN" \
  --addr 127.0.0.1:50051 \
  --node-id orchestrator-1 \
  --tls-cert "$ORCH_CERT" \
  --tls-key "$ORCH_KEY" \
  --tls-client-ca "$CA_CERT" \
  --worker 127.0.0.1:50052 \
  --worker-ca "$CA_CERT" \
  --worker-server-name lattice-worker \
  >"$WORKDIR/orchestrator.log" 2>&1 &
ORCH_PID=$!
sleep 1
if ! kill -0 "$ORCH_PID" >/dev/null 2>&1; then
  echo "orchestrator exited early; showing log:" >&2
  cat "$WORKDIR/orchestrator.log" >&2 || true
  exit 1
fi

echo "running flashaudit client..."
RUST_LOG="${RUST_LOG:-info}" "$FLASH_BIN" \
  --addr https://127.0.0.1:50051 \
  --server-name lattice-orchestrator \
  --ca "$CA_CERT" \
  --cert "$CLIENT_CERT" \
  --key "$CLIENT_KEY" \
  --input "$HASH_FILE" \
  --payload flatbuf \
  --no-tui

echo "smoke test completed successfully"
echo "Logs in $WORKDIR"
