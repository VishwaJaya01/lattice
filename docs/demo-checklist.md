# Demo Checklist

This checklist is the portfolio/demo validation sequence for Lattice.

## 1) Toolchain and generated artifacts

Run from repo root:

```bash
protoc --version
flatc --version
cargo --version
rustc --version
go version
```

Expected:

- tools present
- Rust/Go versions satisfy `rust-toolchain.toml` and `go.mod`

## 2) Build and core tests

```bash
cargo fmt --all --check
cargo build --workspace
cargo test -p rainbowkv -p lattice-input
go test ./cmd/lattice-orchestrator -count=1
./scripts/trace-smoke.sh
```

Expected:

- all commands succeed
- no compile warnings from `flashaudit` dead-code fields
- trace propagation + failover integration tests pass

## 3) Performance checks (RainbowKV)

```bash
cargo bench -p rainbowkv --bench lookup
```

Expected:

- benchmark completes
- outputs include:
  - `rainbowkv_lookup/lookup_ntlm_into/hit`
  - `rainbowkv_lookup/lookup_ntlm_into/miss`
  - `rainbowkv_reduction/reduce_hashes_batch_8k`
- compare against `docs/performance-baseline.md`

## 4) Smoke end-to-end

Linux/macOS:

```bash
./scripts/smoke-e2e.sh
```

Windows PowerShell (Git Bash):

```powershell
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /d/Projects/lattice && ./scripts/smoke-e2e.sh"
```

Expected tail:

- `smoke test completed successfully`
- FlashAudit controls verify in TUI:
  - `p` pauses/resumes send path
  - `x` cancels stream gracefully
  - `s` writes a snapshot file

## 5) Chaos failover

Linux/macOS:

```bash
./scripts/chaos-demo.sh
```

Windows PowerShell (Git Bash):

```powershell
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /d/Projects/lattice && ./scripts/chaos-demo.sh"
```

Expected tail:

- `chaos demo completed successfully`
- summary includes killed worker and both pass batch counts

## 6) Fuzzing (1M runs each target)

Linux/macOS:

```bash
FUZZ_RUNS=1000000 ./scripts/fuzz-ci.sh
```

Windows PowerShell (Git Bash; auto-delegates to WSL):

```powershell
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /d/Projects/lattice && FUZZ_RUNS=1000000 ./scripts/fuzz-ci.sh"
```

Expected:

- both targets finish
- output includes `Done 1000000 runs`

## 7) TLA+ stretch-goal verification

```powershell
java -cp .\tla2tools.jar tlc2.TLC -config .\tla\LatticeShardRecovery.cfg .\tla\LatticeShardRecovery.tla
```

Expected:

- `Model checking completed. No error has been found.`
- reachable state summary reported

## 8) Optional observability stack

```bash
./scripts/observability-up.sh
```

Expected:

- Grafana and Prometheus reachable
- dashboard `Lattice - Orchestrator and Worker Overview` shows worker series during smoke/chaos runs

## 9) Kubernetes packaging sanity (optional)

Render Helm templates:

```bash
helm template lattice deployments/helm/lattice -n lattice > /tmp/lattice-helm.yaml
```

Check raw manifests with kustomize:

```bash
kubectl kustomize deployments/k8s > /tmp/lattice-k8s.yaml
```

Expected:

- both renders succeed
- mTLS secret assumptions match `deployments/k8s/README.md`

## 10) Kubernetes failover proof capture

Linux/macOS:

```bash
./scripts/k8s-failover-proof.sh
```

Windows PowerShell (Git Bash):

```powershell
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /d/Projects/lattice && ./scripts/k8s-failover-proof.sh"
```

Expected:

- script exits successfully
- `docs/k8s-pods-proof.txt` is updated
- `docs/k8s-orchestrator-proof.txt` includes:
  - `worker removed worker=worker-1`
  - `worker registered worker=worker-1`
