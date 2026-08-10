use std::borrow::BorrowMut;
use std::fs;
use std::path::Path;
use std::process::Command;

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
use rand::rngs::OsRng;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};

fn run_in(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_decrypt"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to run decrypt binary")
}

#[test]
fn merged_binary_generate_and_decrypt_roundtrip() {
    let tmp = std::env::temp_dir().join(format!("wannatry-e2e-{}", std::process::id()));
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir_all(&tmp).unwrap();

    let out = run_in(&tmp, &["generate", "2048"]);
    assert!(out.status.success(), "generate failed: {:?}", out);
    assert!(tmp.join("priv.key").exists());
    assert!(tmp.join("pub.key").exists());

    let pub_pem = fs::read_to_string(tmp.join("pub.key")).unwrap();
    let pub_key = RsaPublicKey::from_public_key_pem(&pub_pem).unwrap();
    let padding = Oaep::new::<sha2::Sha256>();

    let mut aes_key = [0u8; 32];
    OsRng.fill_bytes(&mut aes_key);
    let enc_key = pub_key.encrypt(OsRng.borrow_mut(), padding, &aes_key).unwrap();
    fs::write(tmp.join("key.part1"), enc_key).unwrap();

    let cipher = XChaCha20Poly1305::new((&aes_key).into());
    let mut inner_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut inner_nonce);
    let mut outer_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut outer_nonce);
    let plaintext: &[u8] = br#"{"victim":"v","hacker":"h","message":"YOUR FILES ARE ENCRYPTED","price":420}"#;
    let ct = cipher.encrypt((&inner_nonce).into(), plaintext).unwrap();
    let mut part2 = Vec::from(&outer_nonce[..]);
    part2.extend_from_slice(&inner_nonce);
    part2.extend_from_slice(&ct);
    fs::write(tmp.join("key.part2"), part2).unwrap();

    let out = run_in(&tmp, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "decrypt failed: {} stdout={} stderr={}", out.status, stdout, String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("YOUR FILES ARE ENCRYPTED"), "stdout: {stdout}");
    let written = fs::read(tmp.join("decryption.key")).unwrap();
    assert_eq!(written, aes_key);

    fs::remove_dir_all(&tmp).unwrap();
}
