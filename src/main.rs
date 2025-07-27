use env_logger;
use log::info;
use std::cmp::max;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use thiserror::Error;

fn reverse_search(mut reader: impl Read + Seek, pat: &[u8]) -> std::io::Result<Option<u64>> {
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
        (&mut reader).take(read_len).read_to_end(&mut chunk_buf)?;
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

fn read_le_to_u32(mut reader: impl Read) -> std::io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_le_to_u64(mut reader: impl Read) -> std::io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_into_vector(mut reader: impl Read, size: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn parse_u32_len_prefixed_value(bytes: &[u8]) -> Result<(&[u8], &[u8]), AppError> {
    let (first_4_bytes, rem_bytes) = bytes
        .split_at_checked(4)
        .ok_or(AppError::ParseError("len prefix value parse error".into()))?;
    let first_4_bytes: [u8; 4] = first_4_bytes.try_into().unwrap();
    let len = u32::from_le_bytes(first_4_bytes);
    let (value, rem_bytes) = rem_bytes
        .split_at_checked(len as usize)
        .ok_or(AppError::ParseError("len prefix value parse error".into()))?;
    return Ok((value, rem_bytes));
}

fn parse_u32_len_prefix_sequence(mut seq: &[u8]) -> Result<Vec<&[u8]>, AppError> {
    let mut values = Vec::<&[u8]>::new();
    while !seq.is_empty() {
        let (value, rem) = parse_u32_len_prefixed_value(seq)?;
        values.push(value);
        seq = rem;
    }
    return Ok(values);
}

const EOCD_MAGIC_NUMBER: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const APK_SIG_BLOCK_MAGIC: &str = "APK Sig Block 42";
const APK_SIG_V2_BLOCK_ID: u32 = 0x7109871a;
const APK_SIG_V3_BLOCK_ID: u32 = 0xf05368c0;

#[derive(Error, Debug)]
enum AppError {
    #[error("IO Error")]
    IoError(#[from] std::io::Error),
    #[error("Parse Error")]
    ParseError(String),
}

#[derive(Debug)]
struct ApkSigInfo {
    v2_block: Option<V2Block>,
    v3_block: Option<V3Block>,
}

#[derive(Debug)]
struct V2Block {
    signers: Vec<V2Signer>,
}

#[derive(Debug)]
struct V3Block {}

#[derive(Debug)]
struct V2Signer {
    signed_data: V2SignedData,
    signatures: Vec<Signature>,
    public_key: PublicKey,
}

#[derive(Debug)]
struct V2SignedData {
    digests: Vec<Digest>,
    certificates: Vec<Certificate>,
    additional_attributes: Vec<AdditionalAttribute>,
}

#[derive(Debug)]
struct Signature {
    signature_algorithm_id: u32,
    signature_over_signed_data: Vec<u8>,
}

type PublicKey = Vec<u8>;

#[derive(Debug)]
struct Digest {
    signature_algorithm_id: u32,
    digest: Vec<u8>,
}

type Certificate = Vec<u8>;

#[derive(Debug)]
struct AdditionalAttribute {
    id: u32,
    value: Vec<u8>,
}

impl ApkSigInfo {
    pub fn parse<P: AsRef<Path>>(path: P) -> Result<Self, AppError> {
        let mut apk_file = File::open(path)?;

        apk_file.seek(SeekFrom::End(0))?;
        let eocd_magic_number_pos = reverse_search(&mut apk_file, &EOCD_MAGIC_NUMBER)?;
        let Some(eocd_magic_number_pos) = eocd_magic_number_pos else {
            return Err(AppError::ParseError(
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
        let magic = read_into_vector(&mut apk_file, 16)?;
        if magic != APK_SIG_BLOCK_MAGIC.as_bytes() {
            return Err(AppError::ParseError(
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
            return Err(AppError::ParseError(
                "size of block fields don't match".into(),
            ));
        }

        info!("apk signing block size: {}", size_of_block);

        apk_file.seek(SeekFrom::Start(seq_pos))?;
        let seq_len = size_of_block_pos - seq_pos;

        let mut apk_sig_info = Self {
            v2_block: None,
            v3_block: None,
        };

        let mut parsed_len = 0;
        while parsed_len < seq_len {
            let seq_item_len = read_le_to_u64(apk_file.by_ref())?;
            let id = read_le_to_u32(&mut apk_file)?;
            let value_len = read_le_to_u32(&mut apk_file)?;
            let value = read_into_vector(apk_file.by_ref(), value_len as usize)?;
            match id {
                APK_SIG_V2_BLOCK_ID => apk_sig_info.v2_block = Some(Self::parse_v2_block(value)?),
                APK_SIG_V3_BLOCK_ID => apk_sig_info.v3_block = Some(Self::parse_v3_block(value)?),
                _ => {}
            }
            parsed_len += 8 + seq_item_len;
        }

        Ok(apk_sig_info)
    }

    fn parse_v2_block(value: Vec<u8>) -> Result<V2Block, AppError> {
        let signers = parse_u32_len_prefix_sequence(&value)?;
        let signers: Result<Vec<V2Signer>, AppError> =
            signers.into_iter().map(Self::parse_v2_signer).collect();
        Ok(V2Block { signers: signers? })
    }

    fn parse_v3_block(value: Vec<u8>) -> Result<V3Block, AppError> {
        todo!()
    }

    fn parse_v2_signer(signer_bytes: &[u8]) -> Result<V2Signer, AppError> {
        let (signed_data, rem_bytes) = parse_u32_len_prefixed_value(signer_bytes)?;
        let (signatures, rem_bytes) = parse_u32_len_prefixed_value(rem_bytes)?;
        let (public_key, rem_bytes) = parse_u32_len_prefixed_value(rem_bytes)?;

        assert!(rem_bytes.len() == 0, "Bytes remaining to be parsed");

        let signed_data = Self::parse_v2_signed_data(signed_data)?;

        let signatures = parse_u32_len_prefix_sequence(signatures)?;
        let signatures: Result<Vec<Signature>, AppError> =
            signatures.into_iter().map(Self::parse_signature).collect();
        let signatures = signatures?;

        let public_key: Vec<u8> = public_key.into();

        Ok(V2Signer {
            signed_data,
            signatures,
            public_key,
        })
    }

    fn parse_v2_signed_data(signed_data_bytes: &[u8]) -> Result<V2SignedData, AppError> {
        let (digests_seq, rem_bytes) = parse_u32_len_prefixed_value(signed_data_bytes)?;
        let (certificates_seq, rem_bytes) = parse_u32_len_prefixed_value(rem_bytes)?;
        let (additional_attributes_seq, _rem) = parse_u32_len_prefixed_value(rem_bytes)?; //TODO Return error if bytes remaining

        let digests = parse_u32_len_prefix_sequence(digests_seq)?;
        let certificates = parse_u32_len_prefix_sequence(certificates_seq)?;
        let additional_attributes = parse_u32_len_prefix_sequence(additional_attributes_seq)?;

        let digests: Result<Vec<Digest>, AppError> =
            digests.into_iter().map(Self::parse_digest).collect();

        let certificates: Result<Vec<Certificate>, AppError> = certificates
            .into_iter()
            .map(Self::parse_certificate)
            .collect();

        let additional_attributes: Result<Vec<AdditionalAttribute>, AppError> =
            additional_attributes
                .into_iter()
                .map(Self::parse_additional_attribute)
                .collect();

        Ok(V2SignedData {
            digests: digests?,
            certificates: certificates?,
            additional_attributes: additional_attributes?,
        })
    }

    fn parse_signature(signature_bytes: &[u8]) -> Result<Signature, AppError> {
        let (sig_algo_id_bytes, signature_data) = signature_bytes
            .split_at_checked(4)
            .ok_or(AppError::ParseError("Signature parse error".into()))?;
        let sig_algo_id_bytes: [u8; 4] = sig_algo_id_bytes.try_into().unwrap();
        let (signature_bytes, _rem) = parse_u32_len_prefixed_value(signature_data)?; //TODO Return error if bytes remaining
        Ok(Signature {
            signature_algorithm_id: u32::from_le_bytes(sig_algo_id_bytes),
            signature_over_signed_data: signature_bytes.into(),
        })
    }

    fn parse_digest(digest_bytes: &[u8]) -> Result<Digest, AppError> {
        let (sig_algo_id_bytes, digest_data) = digest_bytes
            .split_at_checked(4)
            .ok_or(AppError::ParseError("Digest parse error".into()))?;
        let sig_algo_id_bytes: [u8; 4] = sig_algo_id_bytes.try_into().unwrap();
        let (digest_bytes, _rem) = parse_u32_len_prefixed_value(digest_data)?; //TODO Return error if bytes remaining
        Ok(Digest {
            signature_algorithm_id: u32::from_le_bytes(sig_algo_id_bytes),
            digest: digest_bytes.into(),
        })
    }

    //NOTE Certificate type could change to ASN.1 DER so maintaining this function signature
    fn parse_certificate(certificate_bytes: &[u8]) -> Result<Certificate, AppError> {
        Ok(certificate_bytes.into())
    }

    fn parse_additional_attribute(
        additional_attribute_bytes: &[u8],
    ) -> Result<AdditionalAttribute, AppError> {
        let (id_bytes, value_bytes) =
            additional_attribute_bytes
                .split_at_checked(4)
                .ok_or(AppError::ParseError(
                    "Additional attribute parse error at ID".into(),
                ))?;
        let id_bytes: [u8; 4] = id_bytes.try_into().unwrap();
        let (value, _rem) = parse_u32_len_prefixed_value(value_bytes)?; //TODO Return error if bytes remaining
        Ok(AdditionalAttribute {
            id: u32::from_le_bytes(id_bytes),
            value: value.into(),
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("started");
    let test_path = "fixtures/v2-two-signers.apk";
    let _apk_sig_info = ApkSigInfo::parse(test_path)?;
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
