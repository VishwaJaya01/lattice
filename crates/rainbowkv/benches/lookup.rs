use std::fs::File;
use std::hint::black_box;
use std::io::{Seek, SeekFrom, Write};

use byteorder::{LittleEndian, WriteBytesExt};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rainbowkv::Table;
use rainbowkv::format::{HashAlg, IndexEntry, MAGIC, VERSION};
use rainbowkv::reduction::{CHARSET_ID_LOWER_ALNUM, MAX_PASSWORD_LEN, ReductionParams};
use tempfile::TempDir;

struct Fixture {
    _tmp: TempDir,
    table: Table,
    hit_hash: [u8; 16],
    miss_hash: [u8; 16],
    params: ReductionParams,
    batch_hashes: Vec<[u8; 16]>,
}

impl Fixture {
    fn new() -> Self {
        let chain_len = 96u32;
        let chain_count = 4096u32;
        let password_len = 6u32;
        let flags = (password_len << 8) | (CHARSET_ID_LOWER_ALNUM as u32);
        let params = ReductionParams::from_flags(flags).expect("valid reduction params");

        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("bench.lattice");
        write_table(&path, chain_len, chain_count, flags, &params).expect("table written");

        let table = Table::open(&path).expect("table opened");
        let (_candidate, hit_hash) = chain_value_at(123, 17, chain_len as usize, &params);

        let mut miss_hash = [0xff; 16];
        while table
            .lookup_ntlm_into(miss_hash, &mut [0u8; MAX_PASSWORD_LEN as usize])
            .expect("lookup ok")
            .is_some()
        {
            miss_hash[0] = miss_hash[0].wrapping_sub(1);
        }

        let mut batch_hashes = Vec::with_capacity(8192);
        for i in 0u32..8192 {
            let mut h = [0u8; 16];
            h[..4].copy_from_slice(&i.to_le_bytes());
            h[4..8].copy_from_slice(&(i.wrapping_mul(17)).to_le_bytes());
            h[8..12].copy_from_slice(&(i.wrapping_mul(97)).to_le_bytes());
            h[12..16].copy_from_slice(&(i.wrapping_mul(251)).to_le_bytes());
            batch_hashes.push(h);
        }

        Self {
            _tmp: tmp,
            table,
            hit_hash,
            miss_hash,
            params,
            batch_hashes,
        }
    }
}

fn bench_lookup(c: &mut Criterion) {
    let fixture = Fixture::new();

    let mut group = c.benchmark_group("rainbowkv_lookup");
    group.throughput(Throughput::Elements(1));

    group.bench_function(BenchmarkId::new("lookup_ntlm_into", "hit"), |b| {
        b.iter_batched(
            || [0u8; MAX_PASSWORD_LEN as usize],
            |mut out| {
                black_box(
                    fixture
                        .table
                        .lookup_ntlm_into(black_box(fixture.hit_hash), &mut out)
                        .expect("lookup ok")
                        .is_some(),
                )
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function(BenchmarkId::new("lookup_ntlm_into", "miss"), |b| {
        b.iter_batched(
            || [0u8; MAX_PASSWORD_LEN as usize],
            |mut out| {
                black_box(
                    fixture
                        .table
                        .lookup_ntlm_into(black_box(fixture.miss_hash), &mut out)
                        .expect("lookup ok")
                        .is_some(),
                )
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_reduction_batch(c: &mut Criterion) {
    let fixture = Fixture::new();
    let mut out = vec![0u64; fixture.batch_hashes.len()];

    let mut group = c.benchmark_group("rainbowkv_reduction");
    group.throughput(Throughput::Elements(fixture.batch_hashes.len() as u64));
    group.bench_function("reduce_hashes_batch_8k", |b| {
        b.iter(|| {
            fixture
                .params
                .reduce_hashes(black_box(&fixture.batch_hashes), 31, black_box(&mut out))
                .expect("reduce ok")
        })
    });
    group.finish();
}

fn write_table(
    path: &std::path::Path,
    chain_len: u32,
    chain_count: u32,
    flags: u32,
    params: &ReductionParams,
) -> Result<(), Box<dyn std::error::Error>> {
    let start_bits = params.start_bits();
    let index_offset = 68u64;
    let index_len = (chain_count as u64) * (std::mem::size_of::<IndexEntry>() as u64);
    let starts_offset = index_offset + index_len;
    let starts_len = ((chain_count as u64) * (start_bits as u64) + 7) / 8;

    let mut entries: Vec<([u8; 16], u32)> = Vec::with_capacity(chain_count as usize);
    for i in 0..chain_count {
        let end_hash = chain_end(i as u64, chain_len as usize, params);
        entries.push((end_hash, i));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut starts_bytes = vec![0u8; starts_len as usize];
    for i in 0..chain_count {
        pack_start(i as u64, i as u64, start_bits as usize, &mut starts_bytes);
    }

    let mut file = File::create(path)?;
    file.write_all(MAGIC)?;
    file.write_u32::<LittleEndian>(VERSION)?;
    file.write_u32::<LittleEndian>(flags)?;
    file.write_u32::<LittleEndian>(HashAlg::Ntlm as u32)?;
    file.write_u32::<LittleEndian>(chain_len)?;
    file.write_u64::<LittleEndian>(chain_count as u64)?;
    file.write_u16::<LittleEndian>(start_bits)?;
    file.write_u16::<LittleEndian>(0)?;
    file.write_u64::<LittleEndian>(index_offset)?;
    file.write_u64::<LittleEndian>(index_len)?;
    file.write_u64::<LittleEndian>(starts_offset)?;
    file.write_u64::<LittleEndian>(starts_len)?;

    for (end_hash, chain_index) in entries {
        file.write_all(&end_hash)?;
        file.write_u32::<LittleEndian>(chain_index)?;
    }

    file.seek(SeekFrom::Start(starts_offset))?;
    file.write_all(&starts_bytes)?;
    file.flush()?;

    Ok(())
}

fn pack_start(value: u64, index: u64, start_bits: usize, out: &mut [u8]) {
    let bit_offset = index as usize * start_bits;
    let byte_offset = bit_offset / 8;
    let bit_shift = bit_offset % 8;
    let mut shifted = (value as u128) << bit_shift;
    let needed = (start_bits + bit_shift + 7) / 8;
    for i in 0..needed {
        out[byte_offset + i] |= (shifted & 0xff) as u8;
        shifted >>= 8;
    }
}

fn chain_end(start: u64, chain_len: usize, params: &ReductionParams) -> [u8; 16] {
    let mut candidate = start;
    let mut hash = [0u8; 16];
    let mut buf = [0u8; MAX_PASSWORD_LEN as usize];
    for step in 0..chain_len {
        params.decode(candidate, &mut buf[..params.password_len as usize]);
        hash = params.ntlm_hash(&buf[..params.password_len as usize]);
        if step + 1 < chain_len {
            candidate = params.reduce_hash(&hash, step as u32);
        }
    }
    hash
}

fn chain_value_at(
    start: u64,
    pos: u32,
    chain_len: usize,
    params: &ReductionParams,
) -> (Vec<u8>, [u8; 16]) {
    let mut candidate = start;
    let mut buf = [0u8; MAX_PASSWORD_LEN as usize];
    let mut hash = [0u8; 16];
    let password_len = params.password_len as usize;

    for step in 0..chain_len {
        params.decode(candidate, &mut buf[..password_len]);
        hash = params.ntlm_hash(&buf[..password_len]);
        if step == pos as usize {
            return (buf[..password_len].to_vec(), hash);
        }
        if step + 1 < chain_len {
            candidate = params.reduce_hash(&hash, step as u32);
        }
    }

    (buf[..password_len].to_vec(), hash)
}

criterion_group!(benches, bench_lookup, bench_reduction_batch);
criterion_main!(benches);
