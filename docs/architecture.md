# Lattice Architecture

## Overview

Lattice is a distributed NTLM audit system with a streaming control plane and a
FlatBuffers-optimized data plane:

- `flashaudit` (Rust): client ingestion + operator UX
- `lattice-orchestrator` (Go): routing, membership, failover, fanout
- `lattice-worker` (Rust): stateless lookup node backed by `rainbowkv`
- `rainbowkv` (Rust): mmap-backed lookup engine for `.lattice` tables

The current design targets:

- persistent bidirectional streams
- worker failover in seconds
- mTLS on all gRPC links
- observability via OpenTelemetry + Prometheus

## Wire Contracts

Two transport layers are used over one gRPC service (`LatticeAudit/AuditStream`):

- Protobuf envelope for broad compatibility and service control
- FlatBuffers payload (`AuditRequest.flatbuf` / `AuditResponse.flatbuf`) for
  low-copy data-plane messages

Source of truth:

- `proto/lattice.proto`
- `proto/lattice.fbs`

## Component Responsibilities

### FlashAudit

- Parses NTLM hashes from stdin/file.
- Opens one mTLS stream to orchestrator.
- Sends hash batches and control messages.
- Receives status + cracked events in real time.

### Orchestrator

- Accepts client streams (`AuditStream`).
- Maintains worker pool and consistent hash ring.
- Routes each batch by deterministic key (`batch_id`).
- Retries routing to alternate workers on failure/backpressure.
- Tracks batch-to-client mapping for response fan-in.
- Broadcasts status events.

### Worker

- Keeps one outbound stream to orchestrator.
- Processes assigned batches using `rainbowkv`.
- Emits cracked hashes and status back on the same stream.
- Is stateless with respect to cluster membership.

### RainbowKV

- Memory-maps table file.
- Binary-searches end-hash index.
- Regenerates chain candidates deterministically.
- Supports no-allocation lookup path (`lookup_ntlm_into`) for hot loops.

## Stream Lifecycle

1. Worker boot:
- worker dials orchestrator with mTLS.
- orchestrator opens worker stream and registers worker in ring.

2. Client boot:
- flashaudit dials orchestrator with mTLS.
- orchestrator registers `client_id` and outbound response channel.

3. Batch ingress:
- client sends `HashBatch` (protobuf or flatbuf).
- orchestrator assigns `batch_id` if absent.
- orchestrator stores `batch_id -> client_id` mapping.
- orchestrator routes request to worker via consistent hashing.

4. Batch response:
- worker returns cracked/status/error response.
- orchestrator routes by `batch_id` mapping (or broadcasts status).
- client receives results on same stream.

## Routing and Failover

Routing state (orchestrator):

- worker ring with virtual nodes (`--hash-replicas`)
- worker liveness (`alive`, `lastSeen`)
- `batchToClient` map

Failure handling path:

- `enqueueWithFailover` attempts primary worker then alternate ring targets.
- dead workers are removed from membership immediately on stream failures.
- heartbeat timeout eviction removes stale workers.

Relevant implementation:

- `cmd/lattice-orchestrator/main.go`
- `cmd/lattice-orchestrator/consistent_hash.go`
- `cmd/lattice-orchestrator/failover_integration_test.go`

## Membership and Health

Workers are monitored by two mechanisms:

- receive-path liveness (`workerRecvLoop` updates `lastSeen`)
- active heartbeat control message (`--worker-heartbeat`)

Timeout eviction:

- `--worker-timeout` (defaults to `3x --worker-heartbeat`)
- `workerHealthLoop` removes workers missing the timeout window

## Security Model

Current controls:

- mTLS required for server and client links.
- TLS 1.3 minimum in orchestrator TLS config.
- cert-based mutual auth for clients and workers.

Operational assumption:

- short-lived certs and ephemeral storage are expected in deployment.

## Observability

### Metrics

Orchestrator + worker expose Prometheus metrics:

- active workers/clients
- inflight batches
- routed batches/sec
- worker errors by reason
- worker last-seen timestamps

See:

- `docs/metrics.md`
- `docs/grafana/lattice-overview-dashboard.json`

### Tracing

- OTLP exporters in orchestrator/worker/flashaudit.
- trace context propagated via protobuf fields and flatbuf metadata.

## Performance Notes

RainbowKV currently includes:

- no-allocation lookup API (`lookup_ntlm_into`)
- AVX2-enabled batched reduction (`reduce_hashes`) with scalar fallback
- Criterion benchmark harness (`crates/rainbowkv/benches/lookup.rs`)

## Verified Behaviors

- Smoke end-to-end stream succeeds (`scripts/smoke-e2e.sh`).
- Chaos flow survives worker kill and continues processing
  (`scripts/chaos-demo.sh`).
- Orchestrator reassignment integration test passes:
  `TestAuditStreamReassignsAfterWorkerFailure`.

## Current Constraints

- Windows-native `cargo-fuzz` with MSVC can fail to link libFuzzer symbols.
  `scripts/fuzz-ci.sh` delegates to WSL when run from Git Bash.
- Local Docker/Grafana observability requires Docker daemon running.

## Next Architecture Milestones

- Add deployment topology doc for Kubernetes primitives (Service, StatefulSet,
  cert distribution, readiness).
- Document SLO thresholds and capacity model (target hashes/sec per worker).
- Extend the TLA+ model with liveness/fairness assumptions and tighter mapping
  to queue and retry semantics.
