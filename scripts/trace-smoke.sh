#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

go test ./cmd/lattice-orchestrator -run 'TestAuditStreamReassignsAfterWorkerFailure|TestAuditStreamPropagatesTraceContext' -count=1 -v
