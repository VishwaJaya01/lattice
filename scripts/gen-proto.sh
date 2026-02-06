#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DIR="$ROOT/proto"
GO_OUT="$PROTO_DIR/latticev1"
RUST_OUT="$PROTO_DIR/gen/rust"
GO_FB_OUT="$PROTO_DIR/gen/go"

mkdir -p "$GO_OUT" "$RUST_OUT" "$GO_FB_OUT"

protoc -I "$PROTO_DIR" \
  --go_out=paths=source_relative:"$GO_OUT" \
  --go-grpc_out=paths=source_relative:"$GO_OUT" \
  "$PROTO_DIR/lattice.proto"

flatc --rust --scoped-enums -o "$RUST_OUT" "$PROTO_DIR/lattice.fbs"
flatc --go --scoped-enums -o "$GO_FB_OUT" "$PROTO_DIR/lattice.fbs"

echo "Generated Go protobufs in $GO_OUT"
echo "Generated Rust FlatBuffers in $RUST_OUT"
echo "Generated Go FlatBuffers in $GO_FB_OUT"
