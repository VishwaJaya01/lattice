use byteorder::{ByteOrder, LittleEndian};

pub fn md4_hash(message: &[u8]) -> [u8; 16] {
    let mut state = [0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32];

    let mlen = message.len();
    let bit_len = (mlen as u64) * 8;

    let mut buffer = [0u8; 128];
    buffer[..mlen].copy_from_slice(message);
    buffer[mlen] = 0x80;

    let rem = (mlen + 1) % 64;
    let pad_len = if rem <= 56 { 56 - rem } else { 120 - rem };
    let total_len = mlen + 1 + pad_len + 8;

    LittleEndian::write_u64(
        &mut buffer[mlen + 1 + pad_len..mlen + 1 + pad_len + 8],
        bit_len,
    );

    for chunk in buffer[..total_len].chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, word) in x.iter_mut().enumerate() {
            *word = LittleEndian::read_u32(&chunk[i * 4..i * 4 + 4]);
        }

        let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);

        round1(&mut a, &mut b, &mut c, &mut d, &x);
        round2(&mut a, &mut b, &mut c, &mut d, &x);
        round3(&mut a, &mut b, &mut c, &mut d, &x);

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for (i, word) in state.iter().enumerate() {
        LittleEndian::write_u32(&mut out[i * 4..i * 4 + 4], *word);
    }
    out
}

#[inline]
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[inline]
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

#[inline]
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline]
fn rotl(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

fn round1(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, x: &[u32; 16]) {
    *a = rotl(a.wrapping_add(f(*b, *c, *d)).wrapping_add(x[0]), 3);
    *d = rotl(d.wrapping_add(f(*a, *b, *c)).wrapping_add(x[1]), 7);
    *c = rotl(c.wrapping_add(f(*d, *a, *b)).wrapping_add(x[2]), 11);
    *b = rotl(b.wrapping_add(f(*c, *d, *a)).wrapping_add(x[3]), 19);

    *a = rotl(a.wrapping_add(f(*b, *c, *d)).wrapping_add(x[4]), 3);
    *d = rotl(d.wrapping_add(f(*a, *b, *c)).wrapping_add(x[5]), 7);
    *c = rotl(c.wrapping_add(f(*d, *a, *b)).wrapping_add(x[6]), 11);
    *b = rotl(b.wrapping_add(f(*c, *d, *a)).wrapping_add(x[7]), 19);

    *a = rotl(a.wrapping_add(f(*b, *c, *d)).wrapping_add(x[8]), 3);
    *d = rotl(d.wrapping_add(f(*a, *b, *c)).wrapping_add(x[9]), 7);
    *c = rotl(c.wrapping_add(f(*d, *a, *b)).wrapping_add(x[10]), 11);
    *b = rotl(b.wrapping_add(f(*c, *d, *a)).wrapping_add(x[11]), 19);

    *a = rotl(a.wrapping_add(f(*b, *c, *d)).wrapping_add(x[12]), 3);
    *d = rotl(d.wrapping_add(f(*a, *b, *c)).wrapping_add(x[13]), 7);
    *c = rotl(c.wrapping_add(f(*d, *a, *b)).wrapping_add(x[14]), 11);
    *b = rotl(b.wrapping_add(f(*c, *d, *a)).wrapping_add(x[15]), 19);
}

fn round2(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, x: &[u32; 16]) {
    *a = rotl(
        a.wrapping_add(g(*b, *c, *d))
            .wrapping_add(x[0])
            .wrapping_add(0x5a827999),
        3,
    );
    *d = rotl(
        d.wrapping_add(g(*a, *b, *c))
            .wrapping_add(x[4])
            .wrapping_add(0x5a827999),
        5,
    );
    *c = rotl(
        c.wrapping_add(g(*d, *a, *b))
            .wrapping_add(x[8])
            .wrapping_add(0x5a827999),
        9,
    );
    *b = rotl(
        b.wrapping_add(g(*c, *d, *a))
            .wrapping_add(x[12])
            .wrapping_add(0x5a827999),
        13,
    );

    *a = rotl(
        a.wrapping_add(g(*b, *c, *d))
            .wrapping_add(x[1])
            .wrapping_add(0x5a827999),
        3,
    );
    *d = rotl(
        d.wrapping_add(g(*a, *b, *c))
            .wrapping_add(x[5])
            .wrapping_add(0x5a827999),
        5,
    );
    *c = rotl(
        c.wrapping_add(g(*d, *a, *b))
            .wrapping_add(x[9])
            .wrapping_add(0x5a827999),
        9,
    );
    *b = rotl(
        b.wrapping_add(g(*c, *d, *a))
            .wrapping_add(x[13])
            .wrapping_add(0x5a827999),
        13,
    );

    *a = rotl(
        a.wrapping_add(g(*b, *c, *d))
            .wrapping_add(x[2])
            .wrapping_add(0x5a827999),
        3,
    );
    *d = rotl(
        d.wrapping_add(g(*a, *b, *c))
            .wrapping_add(x[6])
            .wrapping_add(0x5a827999),
        5,
    );
    *c = rotl(
        c.wrapping_add(g(*d, *a, *b))
            .wrapping_add(x[10])
            .wrapping_add(0x5a827999),
        9,
    );
    *b = rotl(
        b.wrapping_add(g(*c, *d, *a))
            .wrapping_add(x[14])
            .wrapping_add(0x5a827999),
        13,
    );

    *a = rotl(
        a.wrapping_add(g(*b, *c, *d))
            .wrapping_add(x[3])
            .wrapping_add(0x5a827999),
        3,
    );
    *d = rotl(
        d.wrapping_add(g(*a, *b, *c))
            .wrapping_add(x[7])
            .wrapping_add(0x5a827999),
        5,
    );
    *c = rotl(
        c.wrapping_add(g(*d, *a, *b))
            .wrapping_add(x[11])
            .wrapping_add(0x5a827999),
        9,
    );
    *b = rotl(
        b.wrapping_add(g(*c, *d, *a))
            .wrapping_add(x[15])
            .wrapping_add(0x5a827999),
        13,
    );
}

fn round3(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, x: &[u32; 16]) {
    *a = rotl(
        a.wrapping_add(h(*b, *c, *d))
            .wrapping_add(x[0])
            .wrapping_add(0x6ed9eba1),
        3,
    );
    *d = rotl(
        d.wrapping_add(h(*a, *b, *c))
            .wrapping_add(x[8])
            .wrapping_add(0x6ed9eba1),
        9,
    );
    *c = rotl(
        c.wrapping_add(h(*d, *a, *b))
            .wrapping_add(x[4])
            .wrapping_add(0x6ed9eba1),
        11,
    );
    *b = rotl(
        b.wrapping_add(h(*c, *d, *a))
            .wrapping_add(x[12])
            .wrapping_add(0x6ed9eba1),
        15,
    );

    *a = rotl(
        a.wrapping_add(h(*b, *c, *d))
            .wrapping_add(x[2])
            .wrapping_add(0x6ed9eba1),
        3,
    );
    *d = rotl(
        d.wrapping_add(h(*a, *b, *c))
            .wrapping_add(x[10])
            .wrapping_add(0x6ed9eba1),
        9,
    );
    *c = rotl(
        c.wrapping_add(h(*d, *a, *b))
            .wrapping_add(x[6])
            .wrapping_add(0x6ed9eba1),
        11,
    );
    *b = rotl(
        b.wrapping_add(h(*c, *d, *a))
            .wrapping_add(x[14])
            .wrapping_add(0x6ed9eba1),
        15,
    );

    *a = rotl(
        a.wrapping_add(h(*b, *c, *d))
            .wrapping_add(x[1])
            .wrapping_add(0x6ed9eba1),
        3,
    );
    *d = rotl(
        d.wrapping_add(h(*a, *b, *c))
            .wrapping_add(x[9])
            .wrapping_add(0x6ed9eba1),
        9,
    );
    *c = rotl(
        c.wrapping_add(h(*d, *a, *b))
            .wrapping_add(x[5])
            .wrapping_add(0x6ed9eba1),
        11,
    );
    *b = rotl(
        b.wrapping_add(h(*c, *d, *a))
            .wrapping_add(x[13])
            .wrapping_add(0x6ed9eba1),
        15,
    );

    *a = rotl(
        a.wrapping_add(h(*b, *c, *d))
            .wrapping_add(x[3])
            .wrapping_add(0x6ed9eba1),
        3,
    );
    *d = rotl(
        d.wrapping_add(h(*a, *b, *c))
            .wrapping_add(x[11])
            .wrapping_add(0x6ed9eba1),
        9,
    );
    *c = rotl(
        c.wrapping_add(h(*d, *a, *b))
            .wrapping_add(x[7])
            .wrapping_add(0x6ed9eba1),
        11,
    );
    *b = rotl(
        b.wrapping_add(h(*c, *d, *a))
            .wrapping_add(x[15])
            .wrapping_add(0x6ed9eba1),
        15,
    );
}
