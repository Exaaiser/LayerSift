use std::error::Error;

use blake2::{Blake2b512, Blake2s256};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_512};

pub fn digest(algorithm: &str, data: &[u8]) -> Result<String, Box<dyn Error>> {
    Ok(match algorithm.to_ascii_lowercase().replace('-', "").as_str() {
        "md5" => hex::encode(Md5::digest(data)),
        "sha1" => hex::encode(Sha1::digest(data)),
        "sha224" => hex::encode(Sha224::digest(data)),
        "sha256" => hex::encode(Sha256::digest(data)),
        "sha384" => hex::encode(Sha384::digest(data)),
        "sha512" => hex::encode(Sha512::digest(data)),
        "sha3256" => hex::encode(Sha3_256::digest(data)),
        "sha3512" => hex::encode(Sha3_512::digest(data)),
        "blake2s" => hex::encode(Blake2s256::digest(data)),
        "blake2b" => hex::encode(Blake2b512::digest(data)),
        _ => return Err("supported hashes: md5, sha1, sha224, sha256, sha384, sha512, sha3-256, sha3-512, blake2s, blake2b".into()),
    })
}

pub fn digest_candidates(value: &str) -> Vec<&'static str> {
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return vec![];
    }
    match value.len() {
        32 => vec!["MD5", "NTLM and other 128-bit formats"],
        40 => vec!["SHA-1", "other 160-bit formats"],
        56 => vec!["SHA-224"],
        64 => vec![
            "SHA-256",
            "SHA3-256",
            "BLAKE2s-256",
            "other 256-bit formats",
        ],
        96 => vec!["SHA-384"],
        128 => vec![
            "SHA-512",
            "SHA3-512",
            "BLAKE2b-512",
            "other 512-bit formats",
        ],
        _ => vec![],
    }
}

pub fn explain_hash(algorithm: &str) -> Result<&'static str, Box<dyn Error>> {
    match algorithm.to_ascii_lowercase().replace('-', "").as_str() {
        "md5" => Ok(
            "MD5: 128-bit digest. Processes input in blocks through a compression function. Legacy only; collisions are practical.",
        ),
        "sha1" => Ok(
            "SHA-1: 160-bit digest. Block-based compression construction. Legacy only; collisions are practical.",
        ),
        "sha224" | "sha256" | "sha384" | "sha512" => Ok(
            "SHA-2 family: block-based compression construction. Output sizes vary by variant. Suitable for file integrity checks; a raw SHA-2 digest is not a password storage format.",
        ),
        "sha3256" | "sha3512" => Ok(
            "SHA-3 family: Keccak sponge construction. Absorbs input, then squeezes a fixed-length digest. A raw SHA-3 digest is not a password storage format.",
        ),
        "blake2s" | "blake2b" => Ok(
            "BLAKE2 family: fast cryptographic digest. BLAKE2s targets smaller word sizes; BLAKE2b targets 64-bit platforms. A raw BLAKE2 digest is not a password storage format.",
        ),
        _ => Err("unknown hash algorithm".into()),
    }
}
