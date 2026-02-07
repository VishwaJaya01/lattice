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

## Seeds and corpus handling

`scripts/fuzz-ci.sh` automatically:

- merges `fuzz/seeds/<target>/` into `fuzz/corpus/<target>/`
- runs each target against the merged corpus
- writes crashes/reproducers into `fuzz/artifacts/<target>/`

Sanitizer can be overridden:

```bash
FUZZ_SANITIZER=address FUZZ_RUNS=200000 ./scripts/fuzz-ci.sh
```
