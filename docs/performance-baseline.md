# RainbowKV Performance Baseline

This file captures baseline measurements for the current `rainbowkv` demo-table workload and documents acceptance targets for portfolio/demo runs.

## Command

```bash
cargo bench -p rainbowkv --bench lookup
```

## Baseline (2026-02-06, Windows 11, Rust 1.93.0)

- `rainbowkv_lookup/lookup_ntlm_into/hit`
  - time: `[309.39 us 316.92 us 325.15 us]`
  - throughput: `[3.0755 Kelem/s 3.1554 Kelem/s 3.2321 Kelem/s]`
- `rainbowkv_lookup/lookup_ntlm_into/miss`
  - time: `[442.58 us 451.52 us 461.80 us]`
  - throughput: `[2.1654 Kelem/s 2.2147 Kelem/s 2.2595 Kelem/s]`
- `rainbowkv_reduction/reduce_hashes_batch_8k`
  - time: `[41.886 us 42.756 us 43.694 us]`
  - throughput: `[187.48 Melem/s 191.60 Melem/s 195.58 Melem/s]`

## Demo Acceptance Targets

Use these thresholds for sanity checks (not strict CI perf gates):

- `lookup_ntlm_into/hit` median should stay `< 500 us`.
- `lookup_ntlm_into/miss` median should stay `< 700 us`.
- `reduce_hashes_batch_8k` median throughput should stay `> 150 Melem/s`.

## Notes

- Results depend on CPU model, turbo policy, thermal state, and background load.
- Run with a warm machine and minimal background tasks for comparisons.
- Prefer comparing relative regressions on the same host over absolute cross-host values.

## Archiving Runs

Use `scripts/perf-rainbowkv.sh` to capture raw benchmark output snapshots in `docs/perf-runs/`.
