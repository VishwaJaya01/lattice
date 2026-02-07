# RainbowKV Table Format (Draft v0)

This document defines the initial on-disk layout for RainbowKV tables. The
format is optimized for mmap + zero-copy access and supports bit-packed chain
starts with a binary-searchable index by end-hash.

## Endianness

All multi-byte integers are little-endian. The file is mmap-friendly: offsets
and lengths refer to byte ranges within the same file.

## Header (Fixed)

Offset table (draft, 68 bytes total):

- `magic[8]` = `"LATRKV01"`
- `version` (u32)
- `flags` (u32)
- `hash_alg` (u32) — `1 = NTLM`
- `chain_len` (u32)
- `chain_count` (u64)
- `start_bits` (u16) — bits per chain start (bit-packed)
- `reserved` (u16)
- `index_offset` (u64)
- `index_len` (u64)
- `starts_offset` (u64)
- `starts_len` (u64)

### Flags

`flags` bitfield (little endian):

- bits `0..7`: `charset_id`
  - `1` = `abcdefghijklmnopqrstuvwxyz0123456789`
- bits `8..15`: `password_len` (ASCII length)

## Sections

### Index Section

An array of `IndexEntry` sorted by `end_hash` (lexicographic, byte order).
Binary search on this section is the primary lookup path.

`IndexEntry` layout (draft, 20 bytes):

- `end_hash[16]`
- `chain_index` (u32) — index into the bit-packed starts section

### Starts Section (Bit-Packed)

Chain starts are stored as a dense bitstream. Each start consumes `start_bits`
from the header, with no padding between entries. The `chain_index` from the
index section points to the *ordinal* start, not the bit offset.

To locate start `i`:

- `bit_offset = i * start_bits`
- `byte_offset = bit_offset / 8`
- `bit_shift = bit_offset % 8`

The reader reconstructs the start value by spanning up to 2–3 bytes.

## Notes

- The reduction function is deterministic, so only the start value and chain
  length are needed to regenerate a chain.
- Future versions may add a side-car metadata block for table provenance,
  salt/charset info, and build parameters. Flags are reserved for that purpose.

## Performance Validation

- Zero-allocation hot path API: `Table::lookup_ntlm_into(hash, out_buf)` reuses
  caller-provided output memory.
- Compatibility API: `Table::lookup_ntlm(hash)` wraps the zero-allocation path
  and allocates only when returning a hit payload.
- Batched reduction API: `ReductionParams::reduce_hashes(...)` uses AVX2 on
  x86_64 when available, with scalar fallback otherwise.

Recommended local checks:

```bash
cargo test -p rainbowkv
cargo bench -p rainbowkv --bench lookup
```
