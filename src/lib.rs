use base64;
use lz4_compress;
use sodiumoxide::crypto;

pub mod database;

#[macro_use]
extern crate anyhow;

type PublicKey = sodiumoxide::crypto::box_::PublicKey;
type SecretKey = sodiumoxide::crypto::box_::SecretKey;
type Nonce = sodiumoxide::crypto::box_::Nonce;

const HEADER_MESSAGE: &str = "[GQG1-MESSAGE";
const HEADER_FILE: &str = "[GQG1-FILE";
const FOOTER: &str = "]";

pub enum Type<'a> {
    Message,
    File {
        file_name: &'a String
    },
}

pub enum EncodeFlags {
    None,
    Compressed,
}

#[derive(PartialEq, Debug)]
pub enum GqgError {
    InvalidOuterEncoding,
    InvalidInnerEncoding,
    InvalidFileName,
    AuthFailure,
    DecompressFailure,
}

#[derive(PartialEq, Debug)]
pub struct Decoded {
    pub sender: PublicKey,
    pub data: DecodedData
}

#[derive(PartialEq, Debug)]
pub enum DecodedData {
    Message {
        contents: Vec<u8>
    },
    File {
        file_name: String,
        contents: Vec<u8>
    }
}

pub fn encode(from: &SecretKey, to: &PublicKey, typ: Type, flags: EncodeFlags, data: &[u8]) -> Result<String, GqgError> {
    let mut datastream: Vec<u8> = Vec::new();
    match &typ {
        Type::Message => {
        },
        Type::File { file_name } => {
            if !validate_file_name(&file_name) {
                return Err(GqgError::InvalidFileName);
            }
            datastream.extend_from_slice(file_name.as_bytes());
            datastream.push(0);
        }
    };
    match flags {
        EncodeFlags::None => {
            datastream.push(0);
            datastream.extend_from_slice(data)
        },
        EncodeFlags::Compressed => {
            datastream.push(1);
            datastream.extend_from_slice(lz4_compress::compress(data).as_slice())
        }
    };
    let nonce = crypto::box_::gen_nonce();
    let mut payload: Vec<u8> = Vec::new();
    payload.extend(&from.public_key()[..]);
    payload.extend_from_slice(&nonce[..]);
    payload.extend_from_slice(crypto::box_::seal(datastream.as_slice(), &nonce, &to, &from).as_slice());
    let mut ascii = String::with_capacity(0x400);
    match &typ {
        Type::Message => {
            ascii.push_str(HEADER_MESSAGE);
        },
        Type::File {file_name: _ } => {
            ascii.push_str(HEADER_FILE);
        }
    };
    ascii.push(':');
    ascii.push_str(&base64::encode(payload));
    ascii.push_str(FOOTER);
    return Ok(ascii);
}

fn remove_whitespace(s: &mut String) {
    s.retain(|c| !c.is_whitespace());
}

fn validate_file_name(file_name: &str) -> bool {
    if file_name.len() > 32 {
        return false;
    }
    if file_name.len() == 0 {
        return false;
    }
    if file_name.find('/').is_some() {
        return false;
    }
    if file_name.find('\\').is_some() {
        return false;
    }
    if file_name.find("..").is_some() {
        return false;
    }
    return true;
}

pub fn decode(myself: &SecretKey, mut payload: String) -> Result<Decoded, GqgError> {
    remove_whitespace(&mut payload);
    let mut payload: &str = &payload;
    let is_file;
    if payload.starts_with(HEADER_MESSAGE) {
        payload = &payload[HEADER_MESSAGE.len()..];
        is_file = false;
    }
    else if payload.starts_with(HEADER_FILE) {
        payload = &payload[HEADER_FILE.len()..];
        is_file = true;
    }
    else {
        return Err(GqgError::InvalidOuterEncoding);
    }
    if !payload.ends_with(FOOTER) {
        return Err(GqgError::InvalidOuterEncoding);
    }
    let payload = &payload[..payload.len()-1];
    if !payload.starts_with(":") {
        return Err(GqgError::InvalidOuterEncoding);
    }
    let payload = &payload[1..];
    let payload = base64::decode(payload).map_err(|_| GqgError::InvalidOuterEncoding)?;
    if payload.len() < crypto::box_::PUBLICKEYBYTES {
        return Err(GqgError::InvalidOuterEncoding);
    }
    let sender = PublicKey::from_slice(&payload[..crypto::box_::PUBLICKEYBYTES]).unwrap();
    let payload = &payload[crypto::box_::PUBLICKEYBYTES..];
    if payload.len() < crypto::box_::NONCEBYTES {
        return Err(GqgError::InvalidOuterEncoding);
    }
    let nonce = Nonce::from_slice(&payload[..crypto::box_::NONCEBYTES]).unwrap();
    let payload = &payload[crypto::box_::NONCEBYTES..];
    let payload = crypto::box_::open(&payload, &nonce, &sender, &myself).map_err(|_| GqgError::InvalidOuterEncoding)?;
    let mut payload: &[u8] = &payload;
    let file: Option<String>;
    if is_file {
        let separator = payload.iter().position(|x| *x == 0);
        let separator = separator.ok_or(GqgError::InvalidOuterEncoding)?;
        let file_name = std::str::from_utf8(&payload[..separator]).map_err(|_| GqgError::InvalidFileName)?;
        payload = &payload[separator+1..];
        file = Some(file_name.to_string());
    }
    else {
        file = None;
    }
    if payload.len() < 1 {
        return Err(GqgError::InvalidInnerEncoding);
    }
    let contents;
    if payload[0] == 0 {
        contents = payload[1..].to_vec();
    }
    else if payload[0] == 1 {
        contents = lz4_compress::decompress(&payload[1..]).map_err(|_| GqgError::DecompressFailure)?;
    }
    else {
        return Err(GqgError::InvalidInnerEncoding);
    }
    let data;
    match file {
        Some(file_name) => {
            data = DecodedData::File { file_name, contents }
        }
        None => {
            data = DecodedData::Message { contents }
        }
    };
    return Ok(Decoded { sender, data });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_malformed_ascii() {
        let (_, to_sk) = crypto::box_::gen_keypair();
        assert_eq!(
            decode(&to_sk, "[GQG1-ENCRYPTED-MESSAGE".to_string()),
            Err(GqgError::InvalidOuterEncoding));
        assert_eq!(
            decode(&to_sk, "[GQG1-ENCRYPTED-MESSAGE]".to_string()),
            Err(GqgError::InvalidOuterEncoding));
        assert_eq!(
            decode(&to_sk, "[GQG1-ENCRYPTED-MESSAGE:]".to_string()),
            Err(GqgError::InvalidOuterEncoding));
        assert_eq!(
            decode(&to_sk, "[GQG1-ENCRYPTED-MESSAGE::]".to_string()),
            Err(GqgError::InvalidOuterEncoding));
        assert_eq!(
            decode(&to_sk, "[GQG1-ENCRYPTED-MESSAGE:::]".to_string()),
            Err(GqgError::InvalidOuterEncoding));
        assert_eq!(
            decode(&to_sk, "[GQG1-ENCRYPTED-MESSAGE:::".to_string()),
            Err(GqgError::InvalidOuterEncoding));
        assert_eq!(
            decode(&to_sk, "[GQG1-ENCRYPTED-FILE".to_string()),
            Err(GqgError::InvalidOuterEncoding));
        assert_eq!(
            decode(&to_sk, "[GQG1-ENCRYPTED-FILE]".to_string()),
            Err(GqgError::InvalidOuterEncoding));
        assert_eq!(
            decode(&to_sk, "[GQG1-ENCRYPTED-FILE:]".to_string()),
            Err(GqgError::InvalidOuterEncoding));
        assert_eq!(
            decode(&to_sk, "[GQG1-ENCRYPTED-FILE::]".to_string()),
            Err(GqgError::InvalidOuterEncoding));
        assert_eq!(
            decode(&to_sk, "[GQG1-ENCRYPTED-FILE:::]".to_string()),
            Err(GqgError::InvalidOuterEncoding));
        assert_eq!(
            decode(&to_sk, "[GQG1-ENCRYPTED-FILE:::".to_string()),
            Err(GqgError::InvalidOuterEncoding));
    }

    fn msg_of_length(len: usize) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(len);
        for _ in 0..len { v.push(0x41); }
        return v;
    }

    #[test]
    fn test_msg_errors_binary() {
        let (_, from_sk) = crypto::box_::gen_keypair();
        let (to_pk, to_sk) = crypto::box_::gen_keypair();
        let msg_data = msg_of_length(0x123);
        let msg = encode(&from_sk, &to_pk, Type::Message, EncodeFlags::Compressed, &msg_data).unwrap();
        let msg_base64: &str = &msg[HEADER_MESSAGE.len()+1..msg.len()-1];
        let mut msg_inner = base64::decode(msg_base64).unwrap();
        for i in 0..8*msg_inner.len() {
            msg_inner[i/8] ^= 1 << (i%8);
            let mut corrupted_msg = String::new();
            corrupted_msg.push_str(HEADER_MESSAGE);
            corrupted_msg.push(':');
            corrupted_msg.push_str(&base64::encode(&msg_inner));
            corrupted_msg.push_str(FOOTER);
            // Flipping the upper bit of the public key won't return an error from Curve25519.
            if i != 255 {
                assert!(
                    decode(&to_sk, corrupted_msg.clone()) == Err(GqgError::AuthFailure) ||
                    decode(&to_sk, corrupted_msg.clone()) == Err(GqgError::InvalidOuterEncoding)
                );
            }
            msg_inner[i/8] ^= 1 << (i%8);
        }
        let mut uncorrupted_msg = String::new();
        uncorrupted_msg.push_str(HEADER_MESSAGE);
        uncorrupted_msg.push(':');
        uncorrupted_msg.push_str(&base64::encode(&msg_inner));
        uncorrupted_msg.push_str(FOOTER);
        assert!(decode(&to_sk, uncorrupted_msg.clone()).is_ok());
    }

    #[test]
    fn test_encode_decode_message() {
        let (from_pk, from_sk) = crypto::box_::gen_keypair();
        let (to_pk, to_sk) = crypto::box_::gen_keypair();

        for i in 0..12 {
            for j in 0..16 {
                let msg_data = msg_of_length((1 << i) + j);
                // Message, sender on, compression off
                let msg = encode(&from_sk, &to_pk, Type::Message, EncodeFlags::None, &msg_data).unwrap();
                let msg = decode(&to_sk, msg).unwrap();
                assert_eq!(msg,
                    Decoded {
                        sender: from_pk.clone(),
                        data: DecodedData::Message {
                            contents: msg_data.clone()
                        }
                });
                // Message, sender off, compression on
                let msg = encode(&from_sk, &to_pk, Type::Message, EncodeFlags::Compressed, &msg_data).unwrap();
                let msg = decode(&to_sk, msg).unwrap();
                assert_eq!(msg,
                    Decoded {
                        sender: from_pk.clone(),
                        data: DecodedData::Message {
                            contents: msg_data.clone()
                        }
                });
            }
        }
    }

}
