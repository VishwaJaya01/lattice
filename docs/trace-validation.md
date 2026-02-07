# Trace Validation

This document defines the executable checks used to verify end-to-end trace context propagation in Lattice.

## Scope

Validated path:

- `flashaudit`/client request carries `traceparent` + `baggage`
- orchestrator routes request to worker without dropping trace metadata
- worker response returns through orchestrator with the same trace metadata

## Automated Integration Test

Run:

```bash
go test ./cmd/lattice-orchestrator -run TestAuditStreamPropagatesTraceContext -count=1 -v
```

Expected:

- test passes
- worker receives request with expected `traceparent` and `baggage`
- client receives response with same `traceparent` and `baggage`

## Combined Routing + Trace Validation

Run:

```bash
./scripts/trace-smoke.sh
```

This executes both:

- `TestAuditStreamReassignsAfterWorkerFailure`
- `TestAuditStreamPropagatesTraceContext`

Use this script before demos where both failover and observability claims are shown.
