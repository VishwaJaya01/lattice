# Lattice

A cloud-native distributed cryptanalysis grid for high-speed Active Directory NTLM hash auditing. Lattice combines:

- Rust zero-copy lookup paths (`RainbowKV`)
- Go bidirectional gRPC orchestration
- FlatBuffers data-plane payloads
- mTLS end-to-end
- worker failover via consistent hashing + membership updates

## Components

- `cmd/flashaudit/` Rust client (TUI + stream client)
- `cmd/lattice-orchestrator/` Go orchestrator
- `crates/worker/` Rust worker
- `crates/rainbowkv/` Rust mmap lookup engine
- `proto/` gRPC and FlatBuffers contracts

## Prerequisites

- Rust toolchain (`rustc`, `cargo`)
- Go toolchain (`go`)
- Protocol tools (`protoc`, `flatc`)
- `openssl`
- Python 3 (or `python`)
- Bash (Linux/macOS shell or Git Bash on Windows)

## Wire Code Generation

Linux/macOS:

```bash
./scripts/gen-proto.sh
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\gen-proto.ps1
```

## Demo Flow

### 1) Smoke E2E

Runs:
- mTLS cert generation
- demo rainbow table generation
- worker + orchestrator startup
- `flashaudit` stream against orchestrator

Linux/macOS:

```bash
./scripts/smoke-e2e.sh
```

Windows PowerShell (Git Bash):

```powershell
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /d/Projects/lattice && ./scripts/smoke-e2e.sh"
```

### 2) Chaos Demo (Worker Failure + Continue)

Runs:
- two workers + orchestrator
- long client stream (`flashaudit`)
- forced kill of `worker-1` mid-stream
- second post-failure client pass to verify continuity on surviving worker

Expected:
- orchestrator logs `worker removed` for `worker-1`
- client runs complete successfully
- pass-2 log includes `node_id=worker-2`

Linux/macOS:

```bash
./scripts/chaos-demo.sh
```

Windows PowerShell (Git Bash):

```powershell
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /d/Projects/lattice && ./scripts/chaos-demo.sh"
```

Useful knobs:
- `LATTICE_SKIP_BUILD=1` skip binary builds
- `LATTICE_ORCH_BIN=/path/to/lattice-orchestrator` binary to use when `LATTICE_SKIP_BUILD=1`
- `LATTICE_CHAOS_HASH_COUNT=12000` increase pass-1 stream length
- `LATTICE_CHAOS_KILL_DELAY_SECONDS=2` delay before kill injection
- `LATTICE_CHAOS_CLIENT_TIMEOUT_SECONDS=240` increase timeout for pass-1 completion

## Observability Assets

- Metric reference and PromQL snippets: `docs/metrics.md`
- Grafana dashboard JSON: `docs/grafana/lattice-overview-dashboard.json`
- Local Prometheus+Grafana stack: `deployments/observability/docker-compose.yml`
- Helper scripts: `scripts/observability-up.sh`, `scripts/observability-down.sh`

Grafana import:
- Dashboards -> New -> Import
- Upload `docs/grafana/lattice-overview-dashboard.json`
- Select your Prometheus datasource

Quick start (auto-provisioned datasource + dashboard):

Linux/macOS:

```bash
./scripts/observability-up.sh
```

Windows PowerShell (Git Bash):

```powershell
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /d/Projects/lattice && ./scripts/observability-up.sh"
```

Stop stack:

```bash
./scripts/observability-down.sh
```

## Kubernetes Deployment

Two deployment tracks are included:

- Raw manifests (kustomize): `deployments/k8s/`
- Helm chart: `deployments/helm/lattice/`

Container build recipes:

- `deployments/docker/Dockerfile.orchestrator`
- `deployments/docker/Dockerfile.worker`

Quick raw-manifest apply:

```bash
kubectl apply -k deployments/k8s
```

Quick Helm install:

```bash
helm upgrade --install lattice deployments/helm/lattice -n lattice --create-namespace
```

Both expect an mTLS secret (`lattice-mtls`) unless Helm-managed cert material is enabled in values.

Kubernetes failover proof capture:

```bash
./scripts/k8s-failover-proof.sh
```

## Trace Validation

Run the trace and failover integration checks:

```bash
./scripts/trace-smoke.sh
```

Reference:

- `docs/trace-validation.md`

## Performance Baseline

Run benchmark and archive output:

```bash
./scripts/perf-rainbowkv.sh
```

Reference:

- `docs/performance-baseline.md`

## Current Status

- gRPC + FlatBuffers contracts in place
- Worker stream loops implemented
- Orchestrator routing + failover retries implemented
- Worker heartbeat timeout eviction implemented
- Integration test: worker kill and reassignment (`TestAuditStreamReassignsAfterWorkerFailure`)
- Smoke and chaos demo scripts available
- Metrics reference and importable Grafana dashboard available
- RainbowKV no-allocation lookup API (`lookup_ntlm_into`) implemented
- RainbowKV benchmark harness implemented (`cargo bench -p rainbowkv --bench lookup`)
- Fuzz harness in place with WSL delegation for Windows Git Bash (`scripts/fuzz-ci.sh`)
- Stretch goal implemented: TLA+ sharding/recovery model (`tla/LatticeShardRecovery.tla`)
- End-to-end validation checklist: `docs/demo-checklist.md`
- Kubernetes packaging available (raw manifests + Helm chart)
- Kubernetes failover proof automation available (`scripts/k8s-failover-proof.sh`)
- Trace propagation integration test implemented (`TestAuditStreamPropagatesTraceContext`)
- RainbowKV performance baseline captured (`docs/performance-baseline.md`)

## Fuzzing (1M Runs)

Linux/macOS:

```bash
FUZZ_RUNS=1000000 ./scripts/fuzz-ci.sh
```

Windows PowerShell (Git Bash wrapper, auto-delegates to WSL):

```powershell
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /d/Projects/lattice && FUZZ_RUNS=1000000 ./scripts/fuzz-ci.sh"
```

Note:
- If WSL prints slow-I/O warnings for `/mnt/d/...`, that affects throughput only, not correctness.

## CI

GitHub Actions workflow `ci` runs:

- Rust/Go build and targeted tests
- smoke end-to-end script
- Kubernetes manifest render checks (Helm + kustomize)
- TLA+ model check (`tla/LatticeShardRecovery.ci.cfg`)

Workflow `fuzz-smoke` runs fuzz targets and uploads crash/corpus artifacts.
