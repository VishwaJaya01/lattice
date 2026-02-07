use crate::error::{Result, TableError};
use crate::md4::md4_hash;

pub const CHARSET_ID_LOWER_ALNUM: u8 = 1;
const CHARSET_LOWER_ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

pub const MAX_PASSWORD_LEN: u8 = 32;

#[derive(Debug, Clone, Copy)]
pub struct ReductionParams {
    pub charset_id: u8,
    pub password_len: u8,
    pub base: u64,
    pub space: u64,
    space_u128: u128,
    charset: &'static [u8],
}

impl ReductionParams {
    pub fn from_flags(flags: u32) -> Result<Self> {
        let charset_id = (flags & 0xff) as u8;
        let password_len = ((flags >> 8) & 0xff) as u8;
        if password_len == 0 || password_len > MAX_PASSWORD_LEN {
            return Err(TableError::UnsupportedPasswordLen(password_len));
        }

        let charset = match charset_id {
            CHARSET_ID_LOWER_ALNUM => CHARSET_LOWER_ALNUM,
            _ => return Err(TableError::UnsupportedCharset(charset_id)),
        };

        let base = charset.len() as u64;
        let mut space: u128 = 1;
        for _ in 0..password_len {
            space = space
                .checked_mul(base as u128)
                .ok_or(TableError::SpaceOverflow)?;
        }
        if space > u64::MAX as u128 {
            return Err(TableError::SpaceOverflow);
        }

        Ok(Self {
            charset_id,
            password_len,
            base,
            space: space as u64,
            space_u128: space,
            charset,
        })
    }

    pub fn start_bits(&self) -> u16 {
        let mut value = self.space.saturating_sub(1);
        let mut bits = 0u16;
        while value > 0 {
            bits += 1;
            value >>= 1;
        }
        if bits == 0 { 1 } else { bits }
    }

    pub fn decode(&self, mut value: u64, out: &mut [u8]) {
        for i in 0..self.password_len as usize {
            let idx = (value % self.base) as usize;
            out[i] = self.charset[idx];
            value /= self.base;
        }
    }

    pub fn reduce_hash(&self, hash: &[u8; 16], step: u32) -> u64 {
        let step_mix = (step as u128).wrapping_mul(0x9e3779b97f4a7c15);
        let (low, high) = split_hash_le(hash);
        self.reduce_hash_le_parts(low, high, step_mix)
    }

    pub fn reduce_hashes(&self, hashes: &[[u8; 16]], step: u32, out: &mut [u64]) -> Result<()> {
        if out.len() < hashes.len() {
            return Err(TableError::OutputBufferTooSmall {
                needed: hashes.len(),
                actual: out.len(),
            });
        }
        if hashes.is_empty() {
            return Ok(());
        }

        let step_mix = (step as u128).wrapping_mul(0x9e3779b97f4a7c15);
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("avx2") && hashes.len() >= 8 {
                // SAFETY: AVX2 support is checked at runtime above.
                unsafe {
                    self.reduce_hashes_avx2(hashes, &mut out[..hashes.len()], step_mix);
                }
                return Ok(());
            }
        }

        self.reduce_hashes_scalar(hashes, &mut out[..hashes.len()], step_mix);
        Ok(())
    }

    pub fn ntlm_hash(&self, candidate: &[u8]) -> [u8; 16] {
        let mut utf16 = [0u8; MAX_PASSWORD_LEN as usize * 2];
        let mut idx = 0usize;
        for &b in candidate.iter().take(self.password_len as usize) {
            utf16[idx] = b;
            utf16[idx + 1] = 0;
            idx += 2;
        }
        md4_hash(&utf16[..idx])
    }

    #[inline]
    fn reduce_hash_le_parts(&self, low: u64, high: u64, step_mix: u128) -> u64 {
        let mut x = (low as u128) | ((high as u128) << 64);
        x = x.wrapping_add(step_mix);
        (x % self.space_u128) as u64
    }

    fn reduce_hashes_scalar(&self, hashes: &[[u8; 16]], out: &mut [u64], step_mix: u128) {
        for (i, hash) in hashes.iter().enumerate() {
            let (low, high) = split_hash_le(hash);
            out[i] = self.reduce_hash_le_parts(low, high, step_mix);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn reduce_hashes_avx2(&self, hashes: &[[u8; 16]], out: &mut [u64], step_mix: u128) {
        use std::arch::x86_64::{__m256i, _mm256_loadu_si256, _mm256_storeu_si256};

        let mut i = 0usize;
        while i + 8 <= hashes.len() {
            let mut lanes = [[0u64; 4]; 4];
            for block in 0..4 {
                // SAFETY: `hashes` is contiguous and each block reads 32 bytes
                // (two adjacent 16-byte hashes). Bounds are guarded by the loop.
                let vec = unsafe {
                    _mm256_loadu_si256(hashes.as_ptr().add(i + block * 2) as *const __m256i)
                };
                // SAFETY: storeu allows unaligned stores into the temporary lane buffer.
                unsafe {
                    _mm256_storeu_si256(lanes[block].as_mut_ptr() as *mut __m256i, vec);
                }
            }

            for block in 0..4 {
                out[i + block * 2] =
                    self.reduce_hash_le_parts(lanes[block][0], lanes[block][1], step_mix);
                out[i + block * 2 + 1] =
                    self.reduce_hash_le_parts(lanes[block][2], lanes[block][3], step_mix);
            }
            i += 8;
        }

        if i < hashes.len() {
            self.reduce_hashes_scalar(&hashes[i..], &mut out[i..], step_mix);
        }
    }
}

#[inline]
fn split_hash_le(hash: &[u8; 16]) -> (u64, u64) {
    let mut low = [0u8; 8];
    let mut high = [0u8; 8];
    low.copy_from_slice(&hash[..8]);
    high.copy_from_slice(&hash[8..]);
    (u64::from_le_bytes(low), u64::from_le_bytes(high))
}

#[cfg(test)]
mod tests {
    use super::{CHARSET_ID_LOWER_ALNUM, ReductionParams};

    #[test]
    fn reduce_hashes_matches_scalar() {
        let flags = (6u32 << 8) | (CHARSET_ID_LOWER_ALNUM as u32);
        let params = ReductionParams::from_flags(flags).expect("valid flags");

        let mut hashes = Vec::with_capacity(23);
        for i in 0u8..23 {
            let mut hash = [0u8; 16];
            for (j, b) in hash.iter_mut().enumerate() {
                *b = i.wrapping_mul(13).wrapping_add(j as u8);
            }
            hashes.push(hash);
        }

        let mut reduced = vec![0u64; hashes.len()];
        params
            .reduce_hashes(&hashes, 17, &mut reduced)
            .expect("output buffer is large enough");

        for (i, hash) in hashes.iter().enumerate() {
            assert_eq!(reduced[i], params.reduce_hash(hash, 17));
        }
    }
}
