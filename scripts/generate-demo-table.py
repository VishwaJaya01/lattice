#!/usr/bin/env python3
import argparse
import math
import struct

MAGIC = b"LATRKV01"
VERSION = 1
HASH_ALG_NTLM = 1

CHARSET_ID = 1
CHARSET = b"abcdefghijklmnopqrstuvwxyz0123456789"
PASSWORD_LEN = 6


def md4_hash(message: bytes) -> bytes:
    # RFC 1320 MD4 implementation (minimal, for demo table generation).
    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    def rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    bit_len = len(message) * 8
    padded = bytearray(message)
    padded.append(0x80)
    while (len(padded) % 64) != 56:
        padded.append(0)
    padded += struct.pack("<Q", bit_len)

    for chunk_start in range(0, len(padded), 64):
        chunk = padded[chunk_start : chunk_start + 64]
        x = list(struct.unpack("<16I", chunk))
        a, b, c, d = state

        # Round 1
        a = rotl((a + f(b, c, d) + x[0]) & 0xffffffff, 3)
        d = rotl((d + f(a, b, c) + x[1]) & 0xffffffff, 7)
        c = rotl((c + f(d, a, b) + x[2]) & 0xffffffff, 11)
        b = rotl((b + f(c, d, a) + x[3]) & 0xffffffff, 19)
        a = rotl((a + f(b, c, d) + x[4]) & 0xffffffff, 3)
        d = rotl((d + f(a, b, c) + x[5]) & 0xffffffff, 7)
        c = rotl((c + f(d, a, b) + x[6]) & 0xffffffff, 11)
        b = rotl((b + f(c, d, a) + x[7]) & 0xffffffff, 19)
        a = rotl((a + f(b, c, d) + x[8]) & 0xffffffff, 3)
        d = rotl((d + f(a, b, c) + x[9]) & 0xffffffff, 7)
        c = rotl((c + f(d, a, b) + x[10]) & 0xffffffff, 11)
        b = rotl((b + f(c, d, a) + x[11]) & 0xffffffff, 19)
        a = rotl((a + f(b, c, d) + x[12]) & 0xffffffff, 3)
        d = rotl((d + f(a, b, c) + x[13]) & 0xffffffff, 7)
        c = rotl((c + f(d, a, b) + x[14]) & 0xffffffff, 11)
        b = rotl((b + f(c, d, a) + x[15]) & 0xffffffff, 19)

        # Round 2
        a = rotl((a + g(b, c, d) + x[0] + 0x5a827999) & 0xffffffff, 3)
        d = rotl((d + g(a, b, c) + x[4] + 0x5a827999) & 0xffffffff, 5)
        c = rotl((c + g(d, a, b) + x[8] + 0x5a827999) & 0xffffffff, 9)
        b = rotl((b + g(c, d, a) + x[12] + 0x5a827999) & 0xffffffff, 13)
        a = rotl((a + g(b, c, d) + x[1] + 0x5a827999) & 0xffffffff, 3)
        d = rotl((d + g(a, b, c) + x[5] + 0x5a827999) & 0xffffffff, 5)
        c = rotl((c + g(d, a, b) + x[9] + 0x5a827999) & 0xffffffff, 9)
        b = rotl((b + g(c, d, a) + x[13] + 0x5a827999) & 0xffffffff, 13)
        a = rotl((a + g(b, c, d) + x[2] + 0x5a827999) & 0xffffffff, 3)
        d = rotl((d + g(a, b, c) + x[6] + 0x5a827999) & 0xffffffff, 5)
        c = rotl((c + g(d, a, b) + x[10] + 0x5a827999) & 0xffffffff, 9)
        b = rotl((b + g(c, d, a) + x[14] + 0x5a827999) & 0xffffffff, 13)
        a = rotl((a + g(b, c, d) + x[3] + 0x5a827999) & 0xffffffff, 3)
        d = rotl((d + g(a, b, c) + x[7] + 0x5a827999) & 0xffffffff, 5)
        c = rotl((c + g(d, a, b) + x[11] + 0x5a827999) & 0xffffffff, 9)
        b = rotl((b + g(c, d, a) + x[15] + 0x5a827999) & 0xffffffff, 13)

        # Round 3
        a = rotl((a + h(b, c, d) + x[0] + 0x6ed9eba1) & 0xffffffff, 3)
        d = rotl((d + h(a, b, c) + x[8] + 0x6ed9eba1) & 0xffffffff, 9)
        c = rotl((c + h(d, a, b) + x[4] + 0x6ed9eba1) & 0xffffffff, 11)
        b = rotl((b + h(c, d, a) + x[12] + 0x6ed9eba1) & 0xffffffff, 15)
        a = rotl((a + h(b, c, d) + x[2] + 0x6ed9eba1) & 0xffffffff, 3)
        d = rotl((d + h(a, b, c) + x[10] + 0x6ed9eba1) & 0xffffffff, 9)
        c = rotl((c + h(d, a, b) + x[6] + 0x6ed9eba1) & 0xffffffff, 11)
        b = rotl((b + h(c, d, a) + x[14] + 0x6ed9eba1) & 0xffffffff, 15)
        a = rotl((a + h(b, c, d) + x[1] + 0x6ed9eba1) & 0xffffffff, 3)
        d = rotl((d + h(a, b, c) + x[9] + 0x6ed9eba1) & 0xffffffff, 9)
        c = rotl((c + h(d, a, b) + x[5] + 0x6ed9eba1) & 0xffffffff, 11)
        b = rotl((b + h(c, d, a) + x[13] + 0x6ed9eba1) & 0xffffffff, 15)
        a = rotl((a + h(b, c, d) + x[3] + 0x6ed9eba1) & 0xffffffff, 3)
        d = rotl((d + h(a, b, c) + x[11] + 0x6ed9eba1) & 0xffffffff, 9)
        c = rotl((c + h(d, a, b) + x[7] + 0x6ed9eba1) & 0xffffffff, 11)
        b = rotl((b + h(c, d, a) + x[15] + 0x6ed9eba1) & 0xffffffff, 15)

        state[0] = (state[0] + a) & 0xffffffff
        state[1] = (state[1] + b) & 0xffffffff
        state[2] = (state[2] + c) & 0xffffffff
        state[3] = (state[3] + d) & 0xffffffff

    return struct.pack("<4I", *state)


def ntlm_hash(pw_bytes: bytes) -> bytes:
    utf16 = bytearray()
    for b in pw_bytes:
        utf16.append(b)
        utf16.append(0)
    return md4_hash(bytes(utf16))


def decode_candidate(value: int) -> bytes:
    out = bytearray(PASSWORD_LEN)
    base = len(CHARSET)
    for i in range(PASSWORD_LEN):
        out[i] = CHARSET[value % base]
        value //= base
    return bytes(out)


def reduce_hash(hash_bytes: bytes, step: int, space: int) -> int:
    x = int.from_bytes(hash_bytes, "little")
    x = (x + (step * 0x9E3779B97F4A7C15)) & ((1 << 128) - 1)
    return x % space


def chain_end(start: int, chain_len: int, space: int) -> bytes:
    candidate = start
    h = b"\x00" * 16
    for step in range(chain_len):
        pw = decode_candidate(candidate)
        h = ntlm_hash(pw)
        if step + 1 < chain_len:
            candidate = reduce_hash(h, step, space)
    return h


def pack_starts(starts, start_bits, total_bytes):
    out = bytearray(total_bytes)
    for idx, value in enumerate(starts):
        bit_offset = idx * start_bits
        byte_offset = bit_offset // 8
        bit_shift = bit_offset % 8
        shifted = value << bit_shift
        needed = (start_bits + bit_shift + 7) // 8
        for i in range(needed):
            out[byte_offset + i] |= (shifted >> (8 * i)) & 0xFF
    return out


def main():
    parser = argparse.ArgumentParser(description="Generate a demo RainbowKV table")
    parser.add_argument("--output", default="demo.lattice", help="output table path")
    parser.add_argument("--chain-len", type=int, default=100)
    parser.add_argument("--chain-count", type=int, default=5000)
    args = parser.parse_args()

    base = len(CHARSET)
    space = base ** PASSWORD_LEN
    if args.chain_count > space:
        raise SystemExit("chain_count exceeds password space")

    start_bits = max(1, (space - 1).bit_length())
    starts_len = (args.chain_count * start_bits + 7) // 8

    flags = (PASSWORD_LEN << 8) | CHARSET_ID
    index_offset = 68
    index_len = args.chain_count * 20
    starts_offset = index_offset + index_len

    starts = list(range(args.chain_count))
    entries = []
    for idx, start in enumerate(starts):
        end_hash = chain_end(start, args.chain_len, space)
        entries.append((end_hash, idx))

    entries.sort(key=lambda e: e[0])

    header = struct.pack(
        "<8sIIIIQHHQQQQ",
        MAGIC,
        VERSION,
        flags,
        HASH_ALG_NTLM,
        args.chain_len,
        args.chain_count,
        start_bits,
        0,
        index_offset,
        index_len,
        starts_offset,
        starts_len,
    )

    packed_starts = pack_starts(starts, start_bits, starts_len)

    with open(args.output, "wb") as f:
        f.write(header)
        for end_hash, chain_index in entries:
            f.write(end_hash)
            f.write(struct.pack("<I", chain_index))
        f.write(packed_starts)

    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
