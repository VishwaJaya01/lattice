# TLA+ Model: Sharding and Recovery

This folder contains the selected stretch-goal artifact from `AGENT.md`:

- `LatticeShardRecovery.tla`
- `LatticeShardRecovery.cfg`
- `LatticeShardRecovery.ci.cfg`

## What the model covers

- Deterministic routing preference per batch key (`Pref`) generated inside the
  model as a per-batch permutation of `Workers`, representing consistent-hash
  preference order.
- Worker membership changes (`Fail`, `Recover`).
- Batch lifecycle (`SubmitAccepted`, `SubmitRejected`, `Complete`).
- Reassignment of in-flight ownership after membership changes via `PickLive`.

## Key invariants checked

- `TypeOK`
- `AcceptedAccounted`
- `NoRejectedAccepted`
- `DisjointInflightCompleted`
- `InflightOwnedWhenPossible`
- `OwnerMatchesHash`
- `NoCompletedRegression`

## Run with TLC (CLI)

1. Download `tla2tools.jar` from the official TLA+ release.
2. Run from repo root:

```bash
java -cp tla2tools.jar tlc2.TLC -config tla/LatticeShardRecovery.cfg tla/LatticeShardRecovery.tla
```

Optional:

```bash
java -cp tla2tools.jar tlc2.TLC -workers 4 -deadlock -config tla/LatticeShardRecovery.cfg tla/LatticeShardRecovery.tla
```

CI-sized model:

```bash
java -cp tla2tools.jar tlc2.TLC -config tla/LatticeShardRecovery.ci.cfg tla/LatticeShardRecovery.tla
```

## Mapping to implementation

- Model `Pref` corresponds to consistent-hash worker preference order
  (`cmd/lattice-orchestrator/consistent_hash.go`).
- Model `Fail` / `Recover` correspond to orchestrator worker membership updates
  (`cmd/lattice-orchestrator/main.go`).
- Model reassignment aligns with failover routing intent in
  `enqueueWithFailover` and heartbeat/stream-based worker removal.

## Config simplification

`Pref` is model-defined (not set in `.cfg`) to avoid TLC config parser edge
cases with nested function/sequence literals.

## Notes

- This is a control-plane model and intentionally abstracts data-plane details
  (FlatBuffers payload internals, NTLM lookup internals, network retries).
- It is safety-focused; liveness refinements can be added in follow-up models.
