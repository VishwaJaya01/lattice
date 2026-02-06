# Proto Contracts

## Intended Message Flow

- FlashAudit opens a single bidirectional gRPC stream to Lattice-Orchestrator.
- Requests are sent as `AuditRequest` messages; responses are `AuditResponse` messages.
- Production payloads are FlatBuffers-encoded and carried in the `flatbuf` field.
- Protobuf sub-messages (`HashBatch`, `CrackedHash`, etc.) are kept for debugging
  and early integration.
- W3C trace context is carried in `traceparent` / `baggage` fields and mirrored
  inside FlatBuffers for cross-stream propagation.

## Generation

From repo root:

```
./scripts/gen-proto.sh
```

On Windows PowerShell:

```
./scripts/gen-proto.ps1
```

This script runs:
- `protoc` for Go (`proto/latticev1/*.pb.go`)
- `flatc --rust` for Rust (`proto/gen/rust/lattice_generated.rs`)
- `flatc --go` for Go (`proto/gen/go/lattice/fb/*.go`)

Tools required:
- `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc`
- `flatc`
