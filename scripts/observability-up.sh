#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT/deployments/observability/docker-compose.yml"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd docker

if ! docker info >/dev/null 2>&1; then
  cat >&2 <<'MSG'
Docker daemon is not reachable.

On Windows, this usually means Docker Desktop is not running.
1) Start Docker Desktop.
2) Wait until it reports "Engine running".
3) Verify with: docker info
4) Re-run: ./scripts/observability-up.sh

If Docker Desktop is not installed, install it first.
MSG
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD=(docker-compose)
else
  echo "missing Docker Compose (docker compose or docker-compose)" >&2
  exit 1
fi

"${COMPOSE_CMD[@]}" -f "$COMPOSE_FILE" up -d

cat <<MSG
Observability stack is up.

Prometheus: http://localhost:9090
Grafana:    http://localhost:3000 (admin/admin)

Dashboard is auto-provisioned:
- Lattice / Lattice - Orchestrator and Worker Overview

Make sure Lattice metrics endpoints are running on the host:
- orchestrator: 127.0.0.1:2112
- worker-1:     127.0.0.1:2113
- worker-2:     127.0.0.1:2114
MSG
