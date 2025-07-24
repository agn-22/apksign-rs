use env_logger;
use log::info;
use std::cmp::max;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::ops::Add;
use std::path::Path;
use thiserror::Error;

fn reverse_search<R: Read + Seek>(reader: &mut R, pat: &[u8]) -> std::io::Result<Option<u64>> {
    if pat.is_empty() {
        return Ok(None);
    }

    let orig_pos = reader.seek(SeekFrom::Current(0))?;

    const DEFAULT_BUF_SIZE: usize = 4096;
    let max_buf_len = max(DEFAULT_BUF_SIZE, pat.len());
    let mut curr_pos = orig_pos;
    let mut chunk_buf = Vec::<u8>::new();
    let mut carry_buf = Vec::<u8>::new();

    while curr_pos != 0 {
        let next_pos = curr_pos.saturating_sub(max_buf_len as u64);
        let read_len = curr_pos - next_pos;
        chunk_buf.clear();
        reader.seek(SeekFrom::Start(next_pos))?;
        reader.take(read_len).read_to_end(&mut chunk_buf)?;
        chunk_buf.extend_from_slice(&carry_buf);

        if let Some(pos) = chunk_buf
            .windows(pat.len())
            .rposition(|window| window == pat)
        {
            reader.seek(SeekFrom::Start(orig_pos))?;
            return Ok(Some(next_pos + pos as u64));
        }

        carry_buf.clear();
        carry_buf.extend_from_slice(&chunk_buf[..pat.len() - 1]);

        curr_pos = next_pos;
    }

    reader.seek(SeekFrom::Start(orig_pos))?;
    return Ok(None);
}

fn read_le_to_u32<R: Read>(reader: &mut R) -> std::io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_le_to_u64<R: Read>(reader: &mut R) -> std::io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

const EOCD_MAGIC_NUMBER: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const APK_SIG_BLOCK_MAGIC: &str = "APK Sig Block 42";
const APK_SIG_V2_BLOCK_ID: u32 = 0x7109871a;

#[derive(Error, Debug)]
enum AppEror {
    #[error("IO Error")]
    IoError(#[from] std::io::Error),
    #[error("Parse Error")]
    ParseError(String),
}

struct ApkSigInfo {
    v2_block: Option<V2Block>,
    v3_block: Option<V3Block>,
}

struct V2Block {
    signers: Vec<V2Signer>,
}

struct V3Block {}

struct V2Signer {
    signed_data: V2SignedData,
    signatures: Vec<Signature>,
    public_key: PublicKey,
}

struct V2SignedData {
    digests: Vec<Digest>,
    certificates: Vec<Certificate>,
    additional_attributes: Vec<AdditionalAttribute>,
}

struct Signature {
    signature_algorithm_id: u32,
    signature_over_signed_data: Vec<u8>,
}

type PublicKey = Vec<u8>;

struct Digest {
    signature_algorithm_id: u32,
    digest: Vec<u8>,
}

type Certificate = Vec<u8>;

struct AdditionalAttribute {
    id: u32,
    value: Vec<u8>,
}

impl ApkSigInfo {
    pub fn parse<P: AsRef<Path>>(path: P) -> Result<Self, AppEror> {
        let mut apk_file = File::open(path)?;

        apk_file.seek(SeekFrom::End(0))?;
        let eocd_magic_number_pos = reverse_search(&mut apk_file, &EOCD_MAGIC_NUMBER)?;
        let Some(eocd_magic_number_pos) = eocd_magic_number_pos else {
            return Err(AppEror::ParseError(
                "EOCD magic number not found, not a zip file".into(),
            ));
        };

        let mut apk_file = BufReader::new(apk_file);

        let offset_of_start_of_cd_pos = eocd_magic_number_pos + 16;
        apk_file.seek(SeekFrom::Start(offset_of_start_of_cd_pos))?;
        let offset_of_start_of_cd = read_le_to_u32(&mut apk_file)?;

        let start_of_cd_pos = offset_of_start_of_cd as u64;
        let magic_pos = start_of_cd_pos - APK_SIG_BLOCK_MAGIC.len() as u64;
        apk_file.seek(SeekFrom::Start(magic_pos))?;
        let mut magic = [0u8; 16];
        apk_file.read(&mut magic)?;
        if magic != APK_SIG_BLOCK_MAGIC.as_bytes() {
            return Err(AppEror::ParseError(
                "APK signing block magic not found where expected".into(),
            ));
        };

        let size_of_block_pos = magic_pos - 8;
        apk_file.seek(SeekFrom::Start(size_of_block_pos))?;
        let size_of_block = read_le_to_u64(&mut apk_file)?;
        let seq_pos = start_of_cd_pos - size_of_block as u64;

        let size_of_block_at_start_pos = seq_pos - 8;
        apk_file.seek(SeekFrom::Start(size_of_block_at_start_pos))?;
        let size_of_block_at_start = read_le_to_u64(&mut apk_file)?;
        if size_of_block != size_of_block_at_start {
            return Err(AppEror::ParseError(
                "size of block fields don't match".into(),
            ));
        }

        info!("size of block: {}", size_of_block);

        apk_file.seek(SeekFrom::Start(seq_pos))?;
        let seq_len = size_of_block_pos - seq_pos;

        let mut parsed_len = 0;
        while parsed_len < seq_len {
            let seq_item_len = read_le_to_u64(&mut apk_file)?;
            let id = read_le_to_u32(&mut apk_file)?;
            if (id == APK_SIG_V2_BLOCK_ID) {}
            parsed_len += 8 + seq_item_len;
        }

        Ok(ApkSigInfo {
            v2_block: None,
            v3_block: None,
        })
    }

    fn parse_v2_block(value: &[u8]) -> V2Block {
        todo!()
    }

    fn parse_v3_block(value: &[u8]) -> V3Block {
        todo!()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("started");
    let test_path = "fixtures/v2-two-signers.apk";
    let apk_sig_info = ApkSigInfo::parse(test_path)?;
    Ok(())
}

//Write more test cases for reverse_search
#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_file() -> std::fs::File {
        File::open("fixtures/v2-two-signers.apk").unwrap()
    }

    #[test]
    fn reverse_search_for_empty_pattern() {
        let mut file = get_test_file();
        let orig_pos = file.seek(SeekFrom::End(0)).unwrap();
        let pos_found = reverse_search(&mut file, Vec::<u8>::new().as_slice()).unwrap();
        let pos_after_search = file.seek(SeekFrom::Current(0)).unwrap();
        assert_eq!(pos_found, None);
        assert_eq!(orig_pos, pos_after_search);
    }

    #[test]
    fn reverse_search_for_pattern_at_buf_boundary() {
        let mut file = get_test_file();
        file.seek(SeekFrom::End(-4096 * 3)).unwrap(); //Skip 3 buf chunk lengths
        let mut pat = vec![0u8; 100];
        let expected_pos = file.seek(SeekFrom::Current(-(pat.len() as i64))).unwrap();
        file.read_exact(&mut pat).unwrap();

        let orig_pos = file.seek(SeekFrom::End(-4097)).unwrap();
        let pos = reverse_search(&mut file, &pat).unwrap();
        assert_eq!(pos, Some(expected_pos));
        let pos_after_search = file.seek(SeekFrom::Current(0)).unwrap();
        assert_eq!(orig_pos, pos_after_search);
    }

    #[test]
    fn reverse_search_for_long_pattern() {
        let mut file = get_test_file();
        let mut pat = vec![0u8; 4096 * 2 + 100];
        file.seek(SeekFrom::End(-4096 * 3)).unwrap(); //Skip 3 buf chunk lengths
        let expected_pos = file.seek(SeekFrom::Current(-(pat.len() as i64))).unwrap();
        file.read_exact(&mut pat).unwrap();

        let orig_pos = file.seek(SeekFrom::End(-4097)).unwrap();
        let pos = reverse_search(&mut file, &pat).unwrap();
        assert_eq!(pos, Some(expected_pos));
        let pos_after_search = file.seek(SeekFrom::Current(0)).unwrap();
        assert_eq!(orig_pos, pos_after_search);
    }
}
