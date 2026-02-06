# Fuzzing

This folder contains libFuzzer targets for high-risk parsers:

- `hash_parser`: NTLM hash extraction from input lines.
- `flatbuf_payloads`: FlatBuffers request/response decoding.

## Run locally

```bash
cargo install cargo-fuzz
cd fuzz
cargo fuzz run -O -s none hash_parser
cargo fuzz run -O -s none flatbuf_payloads
```

## Windows note

Native Git Bash + MSVC toolchains may fail to link libFuzzer targets.
Use WSL2 for fuzz runs:

```powershell
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /d/Projects/lattice && FUZZ_RUNS=1000000 ./scripts/fuzz-ci.sh"
```

## CI smoke

```bash
./scripts/fuzz-ci.sh
```

Control iterations via `FUZZ_RUNS=1000000`.

Artifacts are written under `fuzz/artifacts/` by default.
