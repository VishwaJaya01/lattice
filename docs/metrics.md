# Lattice Metrics

This document maps the current Prometheus metrics exported by Lattice components and provides starter PromQL for operations and demos.

## Metric Endpoints

- Orchestrator metrics: `--metrics-addr` (default `:2112`)
- Worker metrics: `--metrics-addr` (default `:2113` per worker instance)

Local observability stack:
- Start: `./scripts/observability-up.sh`
- Stop: `./scripts/observability-down.sh`

For local demos with two workers, typical targets are:
- `127.0.0.1:2112` (orchestrator)
- `127.0.0.1:2113` (worker-1)
- `127.0.0.1:2114` (worker-2)

## Orchestrator Metrics

- `lattice_orchestrator_clients` (gauge)
  - Active client streams.
- `lattice_orchestrator_workers` (gauge)
  - Active worker streams currently registered.
- `lattice_orchestrator_inflight_batches` (gauge)
  - Batches routed to workers but not yet released from routing state.
- `lattice_orchestrator_batches_routed_total` (counter)
  - Total batches routed to workers.
- `lattice_orchestrator_backpressure_total{target}` (counter)
  - Messages dropped due to full channels.
  - `target` labels currently include `client` and `worker`.
- `lattice_orchestrator_worker_errors_total{reason}` (counter)
  - Worker-side connection/stream errors and failover events.
  - Example `reason`: `dial`, `stream`, `send`, `recv`, `heartbeat_timeout`, `reroute`.
- `lattice_orchestrator_worker_last_seen_unix{worker}` (gauge)
  - Last worker activity as unix seconds.

## Worker Metrics

- `lattice_worker_processed_total` (counter)
  - Total hashes processed.
- `lattice_worker_cracked_total` (counter)
  - Total hashes cracked.
- `lattice_worker_lookup_errors_total` (counter)
  - RainbowKV lookup errors.
- `lattice_worker_batches_total` (counter)
  - Total batches handled by worker.
- `lattice_worker_hash_rate` (gauge)
  - Current worker hash rate (hashes/sec).
- `lattice_worker_inflight_batches` (gauge)
  - Worker batches currently in progress.
- `lattice_worker_streams` (gauge)
  - Active worker gRPC streams.
- `lattice_worker_batch_latency_seconds` (histogram)
  - Batch processing latency distribution.

## Prometheus Scrape Example

```yaml
scrape_configs:
  - job_name: lattice_orchestrator
    static_configs:
      - targets: ["127.0.0.1:2112"]

  - job_name: lattice_workers
    static_configs:
      - targets: ["127.0.0.1:2113", "127.0.0.1:2114"]
```

## Starter PromQL

- Routed batches/sec:
  - `rate(lattice_orchestrator_batches_routed_total[1m])`
- Worker errors/sec by reason:
  - `sum by (reason) (rate(lattice_orchestrator_worker_errors_total[5m]))`
- Worker backpressure/sec by target:
  - `sum by (target) (rate(lattice_orchestrator_backpressure_total[5m]))`
- Worker liveness age (seconds):
  - `time() - lattice_orchestrator_worker_last_seen_unix`
- Worker hash rate by instance:
  - `lattice_worker_hash_rate`
- Worker cracked/sec:
  - `rate(lattice_worker_cracked_total[1m])`
- Worker lookup errors/sec:
  - `rate(lattice_worker_lookup_errors_total[1m])`
- Worker batch latency p95 by instance:
  - `histogram_quantile(0.95, sum by (instance, le) (rate(lattice_worker_batch_latency_seconds_bucket[5m])))`

## Expected Signals During Chaos Demo

When running `scripts/chaos-demo.sh`:
- `lattice_orchestrator_workers` drops from `2` to `1` after worker kill.
- `lattice_orchestrator_worker_errors_total{reason="recv"}` and/or `{reason="reroute"}` increases.
- Remaining worker keeps non-zero `lattice_worker_hash_rate` and rising `lattice_worker_cracked_total`.
- `lattice_orchestrator_batches_routed_total` continues increasing.
