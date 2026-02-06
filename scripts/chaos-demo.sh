#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d /tmp/lattice-chaos-XXXXXX)"
echo "chaos workdir: $WORKDIR"

on_err() {
  local code=$?
  echo "chaos demo failed (exit $code) at line ${BASH_LINENO[0]}: $BASH_COMMAND" >&2
  if [[ -n "${WORKDIR:-}" ]]; then
    [[ -f "$WORKDIR/worker1.log" ]] && echo "worker1 log: $WORKDIR/worker1.log" >&2
    [[ -f "$WORKDIR/worker2.log" ]] && echo "worker2 log: $WORKDIR/worker2.log" >&2
    [[ -f "$WORKDIR/orchestrator.log" ]] && echo "orchestrator log: $WORKDIR/orchestrator.log" >&2
    [[ -f "$WORKDIR/flashaudit-pass1.log" ]] && echo "flashaudit pass1 log: $WORKDIR/flashaudit-pass1.log" >&2
    [[ -f "$WORKDIR/flashaudit-pass2.log" ]] && echo "flashaudit pass2 log: $WORKDIR/flashaudit-pass2.log" >&2
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

wait_for_pattern() {
  local file="$1"
  local pattern="$2"
  local timeout="$3"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if grep -Eq "$pattern" "$file" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

wait_for_pid_exit() {
  local pid="$1"
  local timeout="$2"
  local deadline=$((SECONDS + timeout))
  while kill -0 "$pid" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 0.25
  done
  return 0
}

need_cmd openssl
need_cmd cargo
need_cmd go

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
  if [[ -n "${FLASH1_PID:-}" ]]; then
    kill "$FLASH1_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${WORKER1_PID:-}" ]]; then
    kill "$WORKER1_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${WORKER2_PID:-}" ]]; then
    kill "$WORKER2_PID" >/dev/null 2>&1 || true
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

TABLE="$WORKDIR/demo.lattice"
HASH_LONG="$WORKDIR/hashes-long.txt"
HASH_SHORT="$WORKDIR/hashes-short.txt"
FLASH1_LOG="$WORKDIR/flashaudit-pass1.log"
FLASH2_LOG="$WORKDIR/flashaudit-pass2.log"
ORCH_LOG="$WORKDIR/orchestrator.log"
WORKER1_LOG="$WORKDIR/worker1.log"
WORKER2_LOG="$WORKDIR/worker2.log"

HASH_COUNT="${LATTICE_CHAOS_HASH_COUNT:-6000}"
HASH_COUNT_SHORT="${LATTICE_CHAOS_HASH_COUNT_SHORT:-128}"
KILL_DELAY_SECONDS="${LATTICE_CHAOS_KILL_DELAY_SECONDS:-1}"
CLIENT_TIMEOUT_SECONDS="${LATTICE_CHAOS_CLIENT_TIMEOUT_SECONDS:-180}"

echo "generating CA cert..."
openssl genrsa -out "$CA_KEY" 4096 >/dev/null
openssl_req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
  -subj "/CN=lattice-ca" -out "$CA_CERT" >/dev/null

create_cert() {
  local cn="$1"
  local key="$2"
  local csr="$3"
  local cert="$4"
  local ext="$5"

  openssl genrsa -out "$key" 2048 >/dev/null
  openssl_req -new -key "$key" -subj "/CN=$cn" -out "$csr" >/dev/null
  cat >"$ext" <<EXT
subjectAltName=DNS:$cn
EXT
  openssl x509 -req -in "$csr" -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -CAcreateserial -out "$cert" -days 365 -sha256 -extfile "$ext" >/dev/null
}

create_cert lattice-orchestrator "$ORCH_KEY" "$WORKDIR/orch.csr" "$ORCH_CERT" "$WORKDIR/orch.ext"
create_cert lattice-worker "$WORKER_KEY" "$WORKDIR/worker.csr" "$WORKER_CERT" "$WORKDIR/worker.ext"
create_cert lattice-client "$CLIENT_KEY" "$WORKDIR/client.csr" "$CLIENT_CERT" "$WORKDIR/client.ext"

echo "generating demo table..."
"$PYTHON_BIN" "$ROOT/scripts/generate-demo-table.py" --output "$TABLE" --chain-len 100 --chain-count 5000

echo "generating hash inputs..."
SEED_HASH="$("$PYTHON_BIN" - "$ROOT/scripts/generate-demo-table.py" <<'PY'
import importlib.util
import pathlib
import sys

script_path = pathlib.Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("generate_demo_table", str(script_path))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

space = len(module.CHARSET) ** module.PASSWORD_LEN
print(module.chain_end(42, 100, space).hex())
PY
)"

: >"$HASH_LONG"
for ((i = 0; i < HASH_COUNT; i++)); do
  printf "%s\n" "$SEED_HASH" >>"$HASH_LONG"
done

: >"$HASH_SHORT"
for ((i = 0; i < HASH_COUNT_SHORT; i++)); do
  printf "%s\n" "$SEED_HASH" >>"$HASH_SHORT"
done

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
if [[ "${LATTICE_SKIP_BUILD:-}" != "1" ]]; then
  ORCH_BIN="$WORKDIR/lattice-orchestrator"
else
  ORCH_BIN="${LATTICE_ORCH_BIN:-}"
  if [[ -z "$ORCH_BIN" ]]; then
    for cand in \
      "$ROOT/lattice-orchestrator" \
      "$ROOT/lattice-orchestrator.exe" \
      "$ROOT/cmd/lattice-orchestrator/lattice-orchestrator" \
      "$ROOT/cmd/lattice-orchestrator/lattice-orchestrator.exe"
    do
      if [[ -f "$cand" ]]; then
        ORCH_BIN="$cand"
        break
      fi
    done
  fi
fi

if [[ ! -f "$WORKER_BIN" ]]; then
  echo "missing worker binary: $WORKER_BIN (run without LATTICE_SKIP_BUILD=1 first)" >&2
  exit 1
fi

if [[ ! -f "$FLASH_BIN" ]]; then
  echo "missing flashaudit binary: $FLASH_BIN (run without LATTICE_SKIP_BUILD=1 first)" >&2
  exit 1
fi

if [[ -z "${ORCH_BIN:-}" || ! -f "$ORCH_BIN" ]]; then
  echo "missing orchestrator binary for skip-build mode." >&2
  echo "run once without LATTICE_SKIP_BUILD=1, or set LATTICE_ORCH_BIN to an existing binary path." >&2
  exit 1
fi

echo "starting worker-1..."
"$WORKER_BIN" \
  --addr 127.0.0.1:50052 \
  --node-id worker-1 \
  --metrics-addr 127.0.0.1:2113 \
  --table "$TABLE" \
  --tls-cert "$WORKER_CERT" \
  --tls-key "$WORKER_KEY" \
  --tls-client-ca "$CA_CERT" \
  >"$WORKER1_LOG" 2>&1 &
WORKER1_PID=$!
sleep 1
if ! kill -0 "$WORKER1_PID" >/dev/null 2>&1; then
  echo "worker-1 exited early; showing log:" >&2
  cat "$WORKER1_LOG" >&2 || true
  exit 1
fi

echo "starting worker-2..."
"$WORKER_BIN" \
  --addr 127.0.0.1:50053 \
  --node-id worker-2 \
  --metrics-addr 127.0.0.1:2114 \
  --table "$TABLE" \
  --tls-cert "$WORKER_CERT" \
  --tls-key "$WORKER_KEY" \
  --tls-client-ca "$CA_CERT" \
  >"$WORKER2_LOG" 2>&1 &
WORKER2_PID=$!
sleep 1
if ! kill -0 "$WORKER2_PID" >/dev/null 2>&1; then
  echo "worker-2 exited early; showing log:" >&2
  cat "$WORKER2_LOG" >&2 || true
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
  --worker 127.0.0.1:50053 \
  --worker-ca "$CA_CERT" \
  --worker-server-name lattice-worker \
  --worker-heartbeat 500ms \
  --worker-timeout 2s \
  >"$ORCH_LOG" 2>&1 &
ORCH_PID=$!
sleep 1
if ! kill -0 "$ORCH_PID" >/dev/null 2>&1; then
  echo "orchestrator exited early; showing log:" >&2
  cat "$ORCH_LOG" >&2 || true
  exit 1
fi

echo "running flashaudit pass-1 (long stream)..."
RUST_LOG="${RUST_LOG:-info}" "$FLASH_BIN" \
  --addr https://127.0.0.1:50051 \
  --server-name lattice-orchestrator \
  --ca "$CA_CERT" \
  --cert "$CLIENT_CERT" \
  --key "$CLIENT_KEY" \
  --input "$HASH_LONG" \
  --batch-size 1 \
  --payload flatbuf \
  --no-tui \
  >"$FLASH1_LOG" 2>&1 &
FLASH1_PID=$!

if ! wait_for_pattern "$FLASH1_LOG" "batch sent" 20; then
  echo "flashaudit pass-1 did not begin sending batches; showing log:" >&2
  cat "$FLASH1_LOG" >&2 || true
  exit 1
fi

sleep "$KILL_DELAY_SECONDS"
echo "injecting chaos: killing worker-1 (pid=$WORKER1_PID)"
kill "$WORKER1_PID" >/dev/null 2>&1 || true
unset WORKER1_PID

if ! wait_for_pattern "$ORCH_LOG" "worker removed.*worker=worker-1|worker removed.*worker-1" 15; then
  echo "orchestrator did not log worker-1 removal in time; showing log:" >&2
  cat "$ORCH_LOG" >&2 || true
  exit 1
fi

if ! wait_for_pid_exit "$FLASH1_PID" "$CLIENT_TIMEOUT_SECONDS"; then
  echo "flashaudit pass-1 timed out after ${CLIENT_TIMEOUT_SECONDS}s; showing log:" >&2
  cat "$FLASH1_LOG" >&2 || true
  exit 1
fi
wait "$FLASH1_PID"
unset FLASH1_PID

echo "running flashaudit pass-2 (post-failure verification)..."
RUST_LOG="${RUST_LOG:-info}" "$FLASH_BIN" \
  --addr https://127.0.0.1:50051 \
  --server-name lattice-orchestrator \
  --ca "$CA_CERT" \
  --cert "$CLIENT_CERT" \
  --key "$CLIENT_KEY" \
  --input "$HASH_SHORT" \
  --batch-size 1 \
  --payload flatbuf \
  --no-tui \
  >"$FLASH2_LOG" 2>&1

if grep -Eq "no workers available|code=503" "$FLASH1_LOG" "$FLASH2_LOG"; then
  echo "unexpected client-side no-worker error observed; showing logs:" >&2
  cat "$FLASH1_LOG" >&2 || true
  cat "$FLASH2_LOG" >&2 || true
  exit 1
fi

if ! grep -aFq "worker removed" "$ORCH_LOG"; then
  echo "orchestrator did not report worker removal during chaos run; showing log:" >&2
  cat "$ORCH_LOG" >&2 || true
  exit 1
fi

if ! grep -aFq "input done" "$FLASH2_LOG"; then
  echo "post-failure pass did not complete input stream; showing log:" >&2
  cat "$FLASH2_LOG" >&2 || true
  exit 1
fi

BATCH_SENT_PASS1="$(grep -c "batch sent" "$FLASH1_LOG" || true)"
BATCH_SENT_PASS2="$(grep -c "batch sent" "$FLASH2_LOG" || true)"

echo "chaos demo completed successfully"
echo "summary:"
echo "  worker killed: worker-1"
echo "  pass-1 batches sent: $BATCH_SENT_PASS1"
echo "  pass-2 batches sent: $BATCH_SENT_PASS2"
echo "logs in $WORKDIR"
