# Lattice Project Agent Guide

## Project Overview

**Name**: Lattice  
**Tagline / About**:  
A cloud-native, distributed cryptanalysis grid purpose-built for high-speed Active Directory hash auditing. Combines Rust zero-copy storage, Go bidirectional gRPC streaming, automated consistent-hashing sharding, and Kubernetes-native fault tolerance.

**Main Goal**:  
Build a high-performance, resilient, secure, and production-grade distributed system for cracking NTLM hashes (mainly from Active Directory dumps) — optimized for red-team / pentest / incident response use cases.

**Target Audience**:  
- Security engineers / red teamers  
- Systems programmers  
- People hiring for security tooling, distributed systems, low-level Rust/Go roles

**Core Philosophy**:  
Push engineering quality to the limit — zero-copy, SIMD, streaming, observability, security posture, fault tolerance — while remaining realistically usable on real engagements.

---

## Architecture – High Level

### Components

| Component              | Language | Purpose & Key Characteristics                                                                 |
|-----------------------|----------|-----------------------------------------------------------------------------------------------|
| FlashAudit            | Rust     | Client-side tool – ingests hashes, shows polished TUI, streams results live                  |
| RainbowKV             | Rust     | Zero-copy, memory-mapped rainbow table storage & fast lookup engine                          |
| Lattice-Orchestrator  | Go       | Distributed coordinator – gRPC streaming, consistent hashing, node membership, load balancing |
| Workers               | Rust     | Stateless lookup nodes – run RainbowKV instances, receive tasks via gRPC stream             |
| Deployment            | –        | Kubernetes-native (Helm chart preferred), ephemeral storage, chaos-tested                    |

### Data Flow (Simplified)

```
secretsdump / lsassy / file 
  → FlashAudit (TUI) 
  → gRPC bidirectional stream 
  → Lattice-Orchestrator 
  → Workers (RainbowKV lookups) 
  → results streamed back
```

---

## Locked-in Elite Features (Must Implement)

### 1. FlashAudit (Rust – TUI Client)

- **Input handling**:
  - Read NTLM hashes from file or stdin (pipe support: `impacket-secretsdump | flashaudit --stream`)
  
- **Polished ratatui interface**:
  - Live crack rate (hashes/sec)
  - Sparkline graph of rate over time
  - Nodes connected / health bars
  - Rolling list of recently cracked accounts (username : password / LM:NTLM)
  - Progress bar / ETA
  - Hotkeys (pause, cancel, save results, etc.)
  
- **Real-time mode**: Support `--stream` for live streaming from tools

---

### 2. RainbowKV (Rust – Storage & Lookup Engine)

- **Zero-copy + zero-allocation hot path**: Use `rkyv`, `zerocopy`, or manual pointer arithmetic
- **Custom binary format**: `.lattice` or `.rainbow` files – data on disk = data in memory layout
- **Memory-mapped access**: Use `memmap2` or `moka` + mmap
- **Bit-packed chain storage**: Reduce RAM usage significantly
- **SIMD vectorized chain reduction**: AVX2 / AVX-512 – process at least 8–16 hashes per iteration
- **Fast exact-match lookup**: Optimized for NTLM hash queries

---

### 3. Lattice-Orchestrator (Go – Brain of the Cluster)

- **Bidirectional gRPC streaming**: One persistent connection per FlashAudit client
- **Custom zero-copy wire format**: FlatBuffers strongly preferred, Cap'n Proto acceptable, hand-rolled ok
- **Consistent hashing**: Intelligent work assignment across workers
- **Node membership**: Simple gossip or static list + heartbeat for MVP
- **Automatic re-assignment**: Handle node failures gracefully
- **mTLS everywhere**: Mutual authentication on all connections

---

### 4. Workers (Rust)

- **Stateless design**: Each worker runs RainbowKV independently
- **Stream-based communication**: Receives hash batches from orchestrator via gRPC stream
- **Asynchronous results**: Returns cracked results via the same bidirectional stream

---

### 5. Security Posture

- **Mutual TLS**: On all gRPC communication (short-lived certificates)
- **Ephemeral storage only**: tmpfs / emptyDir in Kubernetes
- **Memory-safe input parser**: Fuzzed for robustness

---

### 6. Observability

- **OpenTelemetry tracing + baggage**: Track full request lifecycle (client → orchestrator → worker → result)
- **Prometheus metrics**:
  - Crack rate (hashes/sec)
  - Latency percentiles
  - Node health status
  - Queue depth
  - Active connections
- **Grafana dashboard**: Pre-configured or at least documented queries

---

### 7. Fuzzing

- **Fuzz harness**: On hash input parser / deserializer
- **CI integration**: Run in CI (or at least demonstrate local execution)

---

### 8. Demo & Polish

- **Demo rainbow table**: Small (~100 MB – 1 GB) with top passwords + common patterns
- **Chaos demo script**: Kill worker pod → system rebalances → cracking continues
- **Clean documentation**:
  - Excellent README
  - Architecture diagram
  - Demo recording / asciinema

---

## One Chosen Stretch Goal (Pick ONE)

**Recommended order of stretch goals** (only implement one for MVP):

1. **TLA+ specification** of consistent hashing + failure recovery (very high signal for distributed systems expertise)
2. **DPDK / AF_XDP** kernel-bypass networking (insane performance flex – even on single node)
3. **WASM plugins** for hash/reduction functions via `wasmtime` (extensibility showcase)

---

## Non-Goals / Post-MVP / Avoid for Now

- Full distributed table sharding (shard queries, not data)
- Zero-knowledge proofs
- Multi-region / CRDTs / Byzantine fault tolerance
- Kerberos support (TGS-REP / AS-REP) – focus on NTLM first
- Huge rainbow tables (demo size only for MVP)

---

## Folder Structure

```
lattice/
├── cmd/
│   ├── flashaudit/           # Rust TUI client
│   └── lattice-orchestrator/ # Go orchestrator
├── crates/
│   ├── rainbowkv/            # Core zero-copy lookup engine
│   └── worker/               # Worker binary / lib
├── proto/                    # .proto files + generated code
├── deployments/
│   ├── helm/                 # Helm chart
│   └── k8s/                  # raw manifests (fallback)
├── scripts/
│   ├── chaos-demo.sh
│   ├── generate-demo-table.py
│   └── ...
├── fuzz/                     # Fuzz targets
├── benches/                  # Criterion benchmarks
├── docs/
│   └── architecture.md
├── README.md
├── AGENT.md                  # ← this file
└── ...
```

---

## Instructions for the Agent

When assisting with code for this project, please adhere to the following guidelines:

### Scope & Features
- **Respect the locked scope**: Focus on the elite features listed above
- **Stay within MVP boundaries**: Avoid post-MVP features unless explicitly requested
- **Implement one stretch goal only**: If choosing, prefer TLA+ spec > DPDK > WASM plugins

### Performance & Architecture
- **Zero-copy / zero-allocation patterns**: Prioritize in Rust hot paths
- **Modern idioms**: Use latest stable Rust & Go features
- **Composition over inheritance**: Prefer trait composition and interfaces
- **SIMD optimization**: Leverage AVX2/AVX-512 where applicable
- **Streaming-first design**: Use bidirectional streams for all real-time data

### Code Quality
- **Clear, documented, testable code**: Every public API should have documentation
- **Good error handling**: 
  - Rust: Use `thiserror` for library errors, `anyhow` for applications
  - Go: Return errors with context, use `errors.Is` / `errors.As`
- **Memory safety**: Leverage Rust's type system; fuzz critical parsers
- **Security-first**: Always consider the threat model (mTLS, ephemeral storage, etc.)

### Development Workflow
- **Ask clarifying questions**: If requirements are ambiguous, ask before implementing
- **Explain big refactors**: Before suggesting major changes, explain why and show before/after
- **Continue from partial code**: When given partial implementations, extend them — don't rewrite unrelated parts
- **Test-driven approach**: Suggest tests alongside implementation
- **Benchmarking**: Use Criterion for Rust performance-critical code

### Communication Style
- **Be direct and technical**: Target audience is experienced systems programmers
- **Show trade-offs**: When multiple approaches exist, explain pros/cons
- **Provide examples**: Include code snippets, especially for complex zero-copy patterns
- **Reference best practices**: Cite relevant RFCs, papers, or industry standards when applicable

### Specific Technology Preferences

**Rust:**
- Use `tokio` for async runtime
- `ratatui` for TUI
- `tonic` for gRPC
- `rkyv` or `zerocopy` for zero-copy serialization
- `memmap2` for memory-mapped I/O
- `criterion` for benchmarks
- `cargo-fuzz` for fuzzing

**Go:**
- Use standard library where possible
- `grpc-go` for gRPC
- FlatBuffers for wire protocol (strongly preferred)
- Standard context patterns for cancellation
- `prometheus/client_golang` for metrics

**DevOps:**
- Helm 3 for Kubernetes deployments
- OpenTelemetry for observability
- Prometheus + Grafana for monitoring
- mTLS with short-lived certificates (cert-manager in K8s)

---

## Quick Reference

### Key Performance Targets
- **Throughput**: 100K+ hashes/sec per worker node (with SIMD + zero-copy)
- **Latency**: <10ms p99 for single hash lookup in RainbowKV
- **Fault tolerance**: <5 second recovery time after worker failure
- **Memory**: Zero allocations in RainbowKV hot path

### Critical Success Criteria
1. ✅ Live TUI with real-time crack rate and sparklines
2. ✅ Zero-copy lookup engine (measured via benchmarks)
3. ✅ Bidirectional gRPC streaming (client ↔ orchestrator ↔ workers)
4. ✅ Consistent hashing with automatic failover
5. ✅ mTLS on all connections
6. ✅ Working chaos demo (kill pod, observe recovery)
7. ✅ OpenTelemetry traces end-to-end
8. ✅ Fuzz harness passes 1M+ iterations

---

## Project Status Tracking

### MVP Checklist
- [ ] FlashAudit TUI with all listed features
- [ ] RainbowKV zero-copy engine
- [ ] Lattice-Orchestrator with gRPC streaming
- [ ] Worker nodes (stateless)
- [ ] mTLS configuration
- [ ] OpenTelemetry + Prometheus integration
- [ ] Fuzzing harness
- [ ] Demo rainbow table
- [ ] Chaos demo script
- [ ] Architecture documentation
- [ ] README with quickstart
- [ ] ONE stretch goal implemented

### Stretch Goals (Pick ONE)
- [ ] TLA+ specification
- [ ] DPDK / AF_XDP integration
- [ ] WASM plugin system

---

**Last updated**: 2025  
**Version**: 1.0  
**Status**: Active Development

---

## Getting Help

When working with this agent guide:

1. **Clarify scope**: Always confirm if a feature is in-scope before implementing
2. **Performance questions**: Ask about trade-offs between readability and zero-copy optimization
3. **Architecture decisions**: Discuss distributed systems design choices before coding
4. **Security concerns**: Validate threat model assumptions early
5. **Stretch goals**: Confirm which ONE stretch goal to pursue before starting

Happy coding! 🚀
