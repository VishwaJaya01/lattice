use std::cmp::Ordering;
use std::mem::{align_of, size_of};
use std::path::Path;

use byteorder::{ByteOrder, LittleEndian};
use memmap2::Mmap;

use crate::error::{Result, TableError};
use crate::format::{HashAlg, IndexEntry, MAGIC, VERSION};
use crate::reduction::{MAX_PASSWORD_LEN, ReductionParams};

const HEADER_LEN: usize = 68;

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub version: u32,
    pub flags: u32,
    pub hash_alg: u32,
    pub chain_len: u32,
    pub chain_count: u64,
    pub start_bits: u16,
    pub index_offset: u64,
    pub index_len: u64,
    pub starts_offset: u64,
    pub starts_len: u64,
}

impl Header {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(TableError::FileTooSmall(buf.len()));
        }
        if &buf[..MAGIC.len()] != MAGIC {
            return Err(TableError::InvalidMagic);
        }

        let version = LittleEndian::read_u32(&buf[8..12]);
        if version != VERSION {
            return Err(TableError::UnsupportedVersion(version));
        }

        let flags = LittleEndian::read_u32(&buf[12..16]);
        let hash_alg = LittleEndian::read_u32(&buf[16..20]);
        if hash_alg != HashAlg::Ntlm as u32 {
            return Err(TableError::UnsupportedHashAlg(hash_alg));
        }
        let chain_len = LittleEndian::read_u32(&buf[20..24]);
        let chain_count = LittleEndian::read_u64(&buf[24..32]);
        let start_bits = LittleEndian::read_u16(&buf[32..34]);
        let index_offset = LittleEndian::read_u64(&buf[36..44]);
        let index_len = LittleEndian::read_u64(&buf[44..52]);
        let starts_offset = LittleEndian::read_u64(&buf[52..60]);
        let starts_len = LittleEndian::read_u64(&buf[60..68]);

        Ok(Header {
            version,
            flags,
            hash_alg,
            chain_len,
            chain_count,
            start_bits,
            index_offset,
            index_len,
            starts_offset,
            starts_len,
        })
    }
}

pub struct LookupResult {
    pub plaintext: Vec<u8>,
    pub chain_index: u32,
    pub position: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct LookupHit {
    pub chain_index: u32,
    pub position: u32,
    pub plaintext_len: usize,
}

pub struct Table {
    mmap: Mmap,
    header: Header,
    reduction: ReductionParams,
}

impl Table {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = std::fs::File::open(path.as_ref())?;
        let mmap = unsafe { Mmap::map(&file)? };
        let header = Header::parse(&mmap[..])?;
        let reduction = ReductionParams::from_flags(header.flags)?;

        if header.chain_count > reduction.space {
            return Err(TableError::ChainCountTooLarge);
        }

        let expected_bits = reduction.start_bits();
        if header.start_bits < expected_bits {
            return Err(TableError::StartBitsTooSmall {
                expected: expected_bits,
                actual: header.start_bits,
            });
        }

        let file_len = mmap.len() as u64;
        if header.index_offset + header.index_len > file_len {
            return Err(TableError::IndexOutOfBounds);
        }
        if header.starts_offset + header.starts_len > file_len {
            return Err(TableError::StartsOutOfBounds);
        }

        let entry_size = size_of::<IndexEntry>() as u64;
        if header.index_len % entry_size != 0 {
            return Err(TableError::IndexMisaligned);
        }
        if (header.index_offset as usize) % align_of::<IndexEntry>() != 0 {
            return Err(TableError::IndexOffsetMisaligned);
        }

        Ok(Table {
            mmap,
            header,
            reduction,
        })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn reduction(&self) -> &ReductionParams {
        &self.reduction
    }

    pub fn index_entries(&self) -> Result<&[IndexEntry]> {
        let entry_size = size_of::<IndexEntry>();
        let count = (self.header.index_len as usize) / entry_size;
        let offset = self.header.index_offset as usize;
        let ptr = unsafe { self.mmap.as_ptr().add(offset) } as *const IndexEntry;
        if ptr.align_offset(align_of::<IndexEntry>()) != 0 {
            return Err(TableError::IndexOffsetMisaligned);
        }
        let entries = unsafe { std::slice::from_raw_parts(ptr, count) };
        Ok(entries)
    }

    pub fn starts_bytes(&self) -> Result<&[u8]> {
        let offset = self.header.starts_offset as usize;
        let len = self.header.starts_len as usize;
        Ok(&self.mmap[offset..offset + len])
    }

    pub fn find_chain(&self, end_hash: [u8; 16]) -> Result<Option<u32>> {
        let entries = self.index_entries()?;
        let found = entries.binary_search_by(|entry| cmp_hash(&entry.end_hash, &end_hash));
        Ok(found.ok().map(|idx| entries[idx].chain_index))
    }

    pub fn chain_start(&self, chain_index: u32) -> Result<u64> {
        if chain_index as u64 >= self.header.chain_count {
            return Err(TableError::ChainIndexOutOfRange);
        }
        if self.header.start_bits > 64 {
            return Err(TableError::StartBitsTooLarge(self.header.start_bits));
        }

        let start_bits = self.header.start_bits as usize;
        let bit_offset = (chain_index as usize)
            .checked_mul(start_bits)
            .ok_or(TableError::ChainIndexOutOfRange)?;
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        let starts = self.starts_bytes()?;
        let bits_needed = bit_shift + start_bits;
        let bytes_needed = (bits_needed + 7) / 8;
        let end = byte_offset + bytes_needed;
        if end > starts.len() {
            return Err(TableError::StartsOutOfBounds);
        }

        let mut acc: u128 = 0;
        for (i, b) in starts[byte_offset..end].iter().enumerate() {
            acc |= (*b as u128) << (i * 8);
        }
        acc >>= bit_shift;

        let mask = if start_bits == 64 {
            u128::MAX
        } else {
            (1u128 << start_bits) - 1
        };

        Ok((acc & mask) as u64)
    }

    pub fn lookup_ntlm(&self, target: [u8; 16]) -> Result<Option<LookupResult>> {
        let mut plaintext = [0u8; MAX_PASSWORD_LEN as usize];
        let Some(hit) = self.lookup_ntlm_into(target, &mut plaintext)? else {
            return Ok(None);
        };

        Ok(Some(LookupResult {
            plaintext: plaintext[..hit.plaintext_len].to_vec(),
            chain_index: hit.chain_index,
            position: hit.position,
        }))
    }

    pub fn lookup_ntlm_into(&self, target: [u8; 16], out: &mut [u8]) -> Result<Option<LookupHit>> {
        let chain_len = self.header.chain_len as usize;
        if chain_len == 0 {
            return Ok(None);
        }

        let params = &self.reduction;
        let password_len = params.password_len as usize;
        if out.len() < password_len {
            return Err(TableError::OutputBufferTooSmall {
                needed: password_len,
                actual: out.len(),
            });
        }
        let candidate_buf = &mut out[..password_len];

        for pos in (0..chain_len).rev() {
            let mut hash = target;
            // Advance from hash@pos to the chain end hash (hash@chain_len-1).
            // The last chain position has no trailing reduction step.
            for step in pos..(chain_len - 1) {
                let candidate = params.reduce_hash(&hash, step as u32);
                params.decode(candidate, &mut candidate_buf[..]);
                hash = params.ntlm_hash(&candidate_buf[..]);
            }

            if let Some(chain_index) = self.find_chain(hash)? {
                let start = self.chain_start(chain_index)?;
                let mut candidate = start;

                for step in 0..chain_len {
                    params.decode(candidate, &mut candidate_buf[..]);
                    let hash = params.ntlm_hash(&candidate_buf[..]);
                    if hash == target {
                        return Ok(Some(LookupHit {
                            chain_index,
                            position: step as u32,
                            plaintext_len: password_len,
                        }));
                    }

                    if step + 1 < chain_len {
                        candidate = params.reduce_hash(&hash, step as u32);
                    }
                }
            }
        }

        Ok(None)
    }
}

fn cmp_hash(a: &[u8; 16], b: &[u8; 16]) -> Ordering {
    for i in 0..16 {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::Table;
    use crate::format::{HashAlg, IndexEntry, MAGIC, VERSION};
    use crate::reduction::{CHARSET_ID_LOWER_ALNUM, ReductionParams};
    use byteorder::{LittleEndian, WriteBytesExt};
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};
    use tempfile::tempdir;

    #[test]
    fn lookup_finds_known_hash() -> Result<(), Box<dyn std::error::Error>> {
        let chain_len = 64u32;
        let chain_count = 256u32;
        let password_len = 4u32;
        let flags = (password_len << 8) | (CHARSET_ID_LOWER_ALNUM as u32);
        let params = ReductionParams::from_flags(flags)?;

        let tmp = tempdir()?;
        let path = tmp.path().join("demo.lattice");
        write_table(&path, chain_len, chain_count, flags, &params)?;

        let table = Table::open(&path)?;

        let start_index = 42u64;
        let pos = 10u32;
        let (candidate, hash) = chain_value_at(start_index, pos, chain_len as usize, &params);

        let result = table.lookup_ntlm(hash)?;
        let result = result.expect("expected hit");

        assert_eq!(result.chain_index, start_index as u32);
        assert_eq!(result.position, pos);
        assert_eq!(result.plaintext, candidate);
        Ok(())
    }

    #[test]
    fn lookup_into_reuses_caller_buffer() -> Result<(), Box<dyn std::error::Error>> {
        let chain_len = 64u32;
        let chain_count = 256u32;
        let password_len = 4u32;
        let flags = (password_len << 8) | (CHARSET_ID_LOWER_ALNUM as u32);
        let params = ReductionParams::from_flags(flags)?;

        let tmp = tempdir()?;
        let path = tmp.path().join("demo.lattice");
        write_table(&path, chain_len, chain_count, flags, &params)?;

        let table = Table::open(&path)?;
        let (_candidate, hash) = chain_value_at(11, 5, chain_len as usize, &params);
        let mut out = [0u8; 8];

        let hit = table
            .lookup_ntlm_into(hash, &mut out)?
            .expect("expected lookup hit");
        assert_eq!(hit.plaintext_len, password_len as usize);

        let alloc_result = table.lookup_ntlm(hash)?.expect("lookup hit");
        assert_eq!(&out[..hit.plaintext_len], alloc_result.plaintext.as_slice());
        Ok(())
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
        file.write_u16::<LittleEndian>(0)?; // reserved
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
        let mut buf = vec![0u8; params.password_len as usize];
        for step in 0..chain_len {
            params.decode(candidate, &mut buf);
            hash = params.ntlm_hash(&buf);
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
        let mut buf = vec![0u8; params.password_len as usize];
        let mut hash = [0u8; 16];

        for step in 0..chain_len {
            params.decode(candidate, &mut buf);
            hash = params.ntlm_hash(&buf);
            if step == pos as usize {
                return (buf.clone(), hash);
            }
            if step + 1 < chain_len {
                candidate = params.reduce_hash(&hash, step as u32);
            }
        }

        (buf, hash)
    }
}
