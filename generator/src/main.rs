use std::fs;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::LineEnding;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use std::borrow::BorrowMut;
use rand::rngs::OsRng;
fn main() {
    let bits = 4096;

// Generate
    let private_key = RsaPrivateKey::new(OsRng.borrow_mut(), bits).expect("failed to generate a key");
    fs::write("priv.key", private_key.to_pkcs8_pem(LineEnding::LF).unwrap().as_str()).expect("TODO: panic message");
    let public_key = RsaPublicKey::from(&private_key);
    fs::write("pub.key", public_key.to_public_key_pem(LineEnding::LF).unwrap()).expect("TODO: panic message");
}
