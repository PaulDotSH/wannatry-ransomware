use anyhow::{anyhow, Error};
use chacha20poly1305::aead::stream;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const STREAM_NONCE_LEN: usize = 19;
pub const BYTES_NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
/// Best-performing buffer size from BENCH_RESULTS.md (256 KiB wins on both
/// 32 MiB and 256 MiB files; 1 MiB and larger buffers lose throughput).
pub const DEFAULT_BUFFER_LEN: usize = 256 * 1024;
/// Files at or below this size are read into memory and encrypted as a single
/// AEAD message instead of being streamed chunk-by-chunk. The crossover is
/// ~4-8 MiB (`wholefile_crossover` in BENCH_RESULTS.md): whole-file clearly
/// wins below 4 MiB, is a tie-to-win around 8 MiB, and streaming wins above.
/// 8 MiB is chosen as the largest size where whole-file is not slower.
pub const WHOLE_FILE_THRESHOLD: u64 = 8 * 1024 * 1024;
/// Decrypt-side size guard. A whole-file stream is `nonce(19) || msg(+16 tag)`
/// i.e. plaintext + 35 bytes, so ciphertexts up to the threshold plus this
/// slack are first tried as a single message, falling back to streaming if the
/// file was actually chunked (older format).
const WHOLE_FILE_DECRYPT_SLACK: u64 = 64;

/// Files at or below this size get their output file preallocated with
/// `set_len` before writing. The `preallocate` bench in encrypt_bench.rs shows
/// a clear win up to ~8 MiB (small files dominate any real drive by count),
/// roughly neutral at 64 MiB, and a small measured regression at 256 MiB where
/// the disk-bound streaming path gains nothing from the extra call.
pub const PREALLOC_MAX_LEN: u64 = 16 * 1024 * 1024;

#[derive(ZeroizeOnDrop)]
pub struct Encrypter {
    pub buffer_len: usize,
    pub buffer: Vec<u8>,
    pub dec_buffer_len: usize,
    pub dec_buffer: Vec<u8>,
}

impl Encrypter {
    pub fn new() -> Self {
        Self::with_buffer_len(DEFAULT_BUFFER_LEN)
    }

    pub fn with_buffer_len(buffer_len: usize) -> Self {
        Encrypter {
            buffer_len,
            buffer: vec![0; buffer_len],
            dec_buffer_len: buffer_len + 16,
            dec_buffer: vec![0; buffer_len + 16],
        }
    }

    pub fn encrypt_file(
        &mut self,
        source_file_path: &Path,
        dist_file_path: &Path,
        key: &[u8; KEY_LEN],
        nonce: &[u8; STREAM_NONCE_LEN],
    ) -> Result<(), Error> {
        let result = self.encrypt_file_inner(source_file_path, dist_file_path, key, nonce);
        if result.is_err() {
            // Clean up any partial output on failure.
            let _ = fs::remove_file(dist_file_path);
        }
        result
    }

    fn encrypt_file_inner(
        &mut self,
        source_file_path: &Path,
        dist_file_path: &Path,
        key: &[u8; KEY_LEN],
        nonce: &[u8; STREAM_NONCE_LEN],
    ) -> Result<(), Error> {
        let aead = XChaCha20Poly1305::new(key.as_ref().into());
        let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

        let metadata = fs::metadata(source_file_path)?;

        // Whole-file path for small files: a single read + one AEAD call beats
        // the per-chunk loop below the crossover point. The output is still a
        // STREAM message (nonce prefix, `ct || tag`), just one message instead
        // of many, so the whole-file decrypt path recognizes it.
        if metadata.len() <= WHOLE_FILE_THRESHOLD {
            let mut data = fs::read(source_file_path)?;
            let ciphertext = stream_encryptor
                .encrypt_last(&*data)
                .map_err(|err| anyhow!("Encrypting small file: {}", err))?;

            let mut dist_file = fs::File::create(dist_file_path)?;
            // Preallocate the exact final size (nonce + plaintext + AEAD tag)
            // up front: beats incremental extent growth on every file size
            // (see the `preallocate` bench group in encrypt_bench.rs).
            let _ = dist_file.set_len(data.len() as u64 + STREAM_NONCE_LEN as u64 + 16);
            dist_file.write_all(nonce)?;
            dist_file.write_all(&ciphertext)?;

            data.zeroize();
            return Ok(());
        }

        let mut source_file = fs::File::open(source_file_path)?;
        let mut dist_file = fs::File::create(dist_file_path)?;
        // Streaming output is `nonce(19) || Σ(chunk + 16-byte tag)`: one
        // message per buffer-sized chunk plus a final (possibly empty)
        // message. Preallocating the exact size needs that message count.
        // Only worth it up to `PREALLOC_MAX_LEN` (see that const's doc).
        if metadata.len() <= PREALLOC_MAX_LEN {
            let messages = metadata.len() / self.buffer_len as u64 + 1;
            let _ = dist_file.set_len(metadata.len() + STREAM_NONCE_LEN as u64 + 16 * messages);
        }
        dist_file.write_all(nonce)?;
        loop {
            let read_count = source_file.read(&mut self.buffer[..])?;

            if read_count == self.buffer_len {
                let ciphertext = stream_encryptor
                    .encrypt_next(&self.buffer[..read_count])
                    .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
                dist_file.write_all(&ciphertext)?;
            } else {
                let ciphertext = stream_encryptor
                    .encrypt_last(&self.buffer[..read_count])
                    .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
                dist_file.write_all(&ciphertext)?;
                break;
            }
        }

        Ok(())
    }

    pub fn decrypt_file(
        &mut self,
        encrypted_file_path: &Path,
        dist: &Path,
        key: &[u8; KEY_LEN],
    ) -> Result<(), Error> {
        let result = self.decrypt_file_inner(encrypted_file_path, dist, key);
        if result.is_err() {
            let _ = fs::remove_file(dist);
        }
        result
    }

    fn decrypt_file_inner(
        &mut self,
        encrypted_file_path: &Path,
        dist: &Path,
        key: &[u8; KEY_LEN],
    ) -> Result<(), Error> {
        // Whole-file path for small ciphertexts: a whole-file stream is a
        // single AEAD message, so one `decrypt_last` over the whole payload
        // works. If that fails the file was chunked (older format), so fall
        // through to the streaming loop below.
        let size = fs::metadata(encrypted_file_path)?.len();
        if size > STREAM_NONCE_LEN as u64
            && size <= WHOLE_FILE_THRESHOLD + WHOLE_FILE_DECRYPT_SLACK
        {
            let data = fs::read(encrypted_file_path)?;
            let nonce: [u8; STREAM_NONCE_LEN] = data[..STREAM_NONCE_LEN].try_into().unwrap();
            let aead = XChaCha20Poly1305::new(key.as_ref().into());
            let decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());
            if let Ok(plaintext) = decryptor.decrypt_last(&data[STREAM_NONCE_LEN..]) {
                let mut dist_file = fs::File::create(dist)?;
                let _ = dist_file.set_len(plaintext.len() as u64);
                dist_file.write_all(&plaintext)?;
                return Ok(());
            }
        }

        let aead = XChaCha20Poly1305::new(key.as_ref().into());
        let mut encrypted_file = fs::File::open(encrypted_file_path)?;
        let mut dist_file = fs::File::create(dist)?;
        // No preallocation here: the number of stream messages (and therefore
        // the exact plaintext size) is only known while parsing the stream.
        let mut nonce: [u8; STREAM_NONCE_LEN] = [0; STREAM_NONCE_LEN];

        encrypted_file.read_exact(&mut nonce)?;
        let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

        loop {
            let read_count = encrypted_file.read(&mut self.dec_buffer[..])?;

            if read_count == self.dec_buffer_len {
                let plaintext = stream_decryptor
                    .decrypt_next(&self.dec_buffer[..read_count])
                    .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
                dist_file.write_all(&plaintext)?;
            } else if read_count == 0 {
                break;
            } else {
                let plaintext = stream_decryptor
                    .decrypt_last(&self.dec_buffer[..read_count])
                    .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
                dist_file.write_all(&plaintext)?;
                break;
            }
        }

        Ok(())
    }
}

/// Encrypt bytes with the non-streaming XChaCha20Poly1305 AEAD.
/// Returns `nonce || ciphertext`.
pub fn encrypt_bytes(data: &[u8], key: &[u8; KEY_LEN], nonce: &[u8; BYTES_NONCE_LEN]) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let mut encrypted = cipher
        .encrypt(nonce.into(), data)
        .map_err(|err| anyhow!("Encrypting bytes: {}", err))?;
    let mut v = Vec::from(nonce.as_slice());
    v.append(&mut encrypted);
    Ok(v)
}

/// Decrypt bytes produced by [`encrypt_bytes`] (i.e. `nonce || ciphertext`).
pub fn decrypt_bytes(data: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, Error> {
    if data.len() < BYTES_NONCE_LEN {
        return Err(anyhow!("Payload too short to contain a nonce"));
    }
    let (nonce, ciphertext) = data.split_at(BYTES_NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|err| anyhow!("Decrypting bytes: {}", err))
}

/// Overwrite a file with zeroes before deleting it.
pub fn shred_file(path: &Path) -> Result<(), Error> {
    let metadata = fs::metadata(path)?;
    let len = metadata.len() as usize;
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    let zeroes = vec![0u8; len.min(1_000_000)];
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(zeroes.len());
        file.write_all(&zeroes[..chunk])?;
        remaining -= chunk;
    }
    file.sync_all()?;
    drop(file);
    fs::remove_file(path)?;
    Ok(())
}

/// Append `.enc` to a path (`foo.txt` -> `foo.txt.enc`).
pub fn encrypted_path(p: &Path) -> std::path::PathBuf {
    let mut os = p.as_os_str().to_os_string();
    os.push(".enc");
    std::path::PathBuf::from(os)
}

/// Strip a trailing `.enc` from a path, if present.
pub fn decrypted_path(p: &Path) -> Option<std::path::PathBuf> {
    let s = p.to_string_lossy();
    match s.strip_suffix(".enc") {
        Some(stripped) if !stripped.is_empty() => Some(std::path::PathBuf::from(stripped)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::rand_core::RngCore;
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    fn random_key() -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut key);
        key
    }

    fn random_nonce() -> [u8; STREAM_NONCE_LEN] {
        let mut nonce = [0u8; STREAM_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    fn roundtrip(data: &[u8], buffer_len: usize) {
        let dir = tempdir().unwrap();
        let src = dir.path().join("orig.bin");
        let enc = dir.path().join("orig.bin.enc");
        let dec = dir.path().join("dec.bin");
        fs::write(&src, data).unwrap();

        let key = random_key();
        let nonce = random_nonce();
        let mut encrypter = Encrypter::with_buffer_len(buffer_len);
        encrypter.encrypt_file(&src, &enc, &key, &nonce).unwrap();

        let mut decrypter = Encrypter::with_buffer_len(buffer_len);
        decrypter.decrypt_file(&enc, &dec, &key).unwrap();

        let decrypted = fs::read(&dec).unwrap();
        assert_eq!(decrypted, data);
        // Original untouched (PoC behavior).
        assert_eq!(fs::read(&src).unwrap(), data);
    }

    #[test]
    fn roundtrip_small_file() {
        let data = b"hello world, this is a test payload".repeat(64);
        roundtrip(&data, DEFAULT_BUFFER_LEN);
    }

    #[test]
    fn roundtrip_empty_file() {
        roundtrip(&[], DEFAULT_BUFFER_LEN);
    }

    #[test]
    fn roundtrip_exact_buffer_size() {
        let data = vec![0xABu8; DEFAULT_BUFFER_LEN];
        roundtrip(&data, DEFAULT_BUFFER_LEN);
    }

    #[test]
    fn roundtrip_one_byte_over_buffer() {
        let data = vec![0xCDu8; DEFAULT_BUFFER_LEN + 1];
        roundtrip(&data, DEFAULT_BUFFER_LEN);
    }

    #[test]
    fn roundtrip_at_whole_file_threshold() {
        let data = vec![0xABu8; WHOLE_FILE_THRESHOLD as usize];
        roundtrip(&data, DEFAULT_BUFFER_LEN);
    }

    #[test]
    fn roundtrip_one_byte_over_whole_file_threshold() {
        let data = vec![0xCDu8; WHOLE_FILE_THRESHOLD as usize + 1];
        roundtrip(&data, DEFAULT_BUFFER_LEN);
    }

    #[test]
    fn roundtrip_large_file() {
        let data: Vec<u8> = (0..100_000_000).map(|i| (i % 251) as u8).collect();
        roundtrip(&data, DEFAULT_BUFFER_LEN);
    }

    #[test]
    fn encrypt_bytes_roundtrip() {
        let key = random_key();
        let mut nonce = [0u8; BYTES_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let msg = b"attack at dawn".to_vec();
        let blob = encrypt_bytes(&msg, &key, &nonce).unwrap();
        assert_eq!(blob.len(), BYTES_NONCE_LEN + msg.len() + 16);
        let dec = decrypt_bytes(&blob, &key).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn decrypt_bytes_rejects_short_payload() {
        let key = random_key();
        assert!(decrypt_bytes(&[0u8; 10], &key).is_err());
    }

    #[test]
    fn nonce_is_unique_per_file() {
        let dir = tempdir().unwrap();
        let src_a = dir.path().join("a.txt");
        let src_b = dir.path().join("b.txt");
        let enc_a = dir.path().join("a.txt.enc");
        let enc_b = dir.path().join("b.txt.enc");
        fs::write(&src_a, b"payload a").unwrap();
        fs::write(&src_b, b"payload b").unwrap();

        let key = random_key();
        let nonce_a = [0x01; STREAM_NONCE_LEN];
        let nonce_b = [0x02; STREAM_NONCE_LEN];
        let mut enc = Encrypter::new();
        enc.encrypt_file(&src_a, &enc_a, &key, &nonce_a).unwrap();
        enc.encrypt_file(&src_b, &enc_b, &key, &nonce_b).unwrap();

        let stored_a: [u8; STREAM_NONCE_LEN] = fs::read(&enc_a).unwrap()[..STREAM_NONCE_LEN].try_into().unwrap();
        let stored_b: [u8; STREAM_NONCE_LEN] = fs::read(&enc_b).unwrap()[..STREAM_NONCE_LEN].try_into().unwrap();
        assert_eq!(stored_a, nonce_a);
        assert_eq!(stored_b, nonce_b);
        assert_ne!(stored_a, stored_b);
    }

    #[test]
    fn file_with_unicode_name() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("café.txt");
        let enc = dir.path().join("café.txt.enc");
        let dec = dir.path().join("café-dec.txt");
        fs::write(&src, "unicode content ✓".as_bytes()).unwrap();

        let key = random_key();
        let nonce = random_nonce();
        let mut encrypter = Encrypter::new();
        encrypter.encrypt_file(&src, &enc, &key, &nonce).unwrap();
        encrypter.decrypt_file(&enc, &dec, &key).unwrap();
        assert_eq!(fs::read(&dec).unwrap(), fs::read(&src).unwrap());
    }

    #[test]
    fn encrypt_fails_when_source_missing() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.bin");
        let dst = dir.path().join("nope.bin.enc");
        let key = random_key();
        let nonce = random_nonce();
        let mut enc = Encrypter::new();
        assert!(enc.encrypt_file(&missing, &dst, &key, &nonce).is_err());
        assert!(!dst.exists());
    }

    #[test]
    fn encrypt_cleans_up_partial_output_on_failure() {
        let dir = tempdir().unwrap();
        // Use a directory as the "source": opening it succeeds on most
        // platforms but reading it fails mid-stream, after the destination
        // file has already been created.
        let src_dir = dir.path().join("sourcedir");
        fs::create_dir(&src_dir).unwrap();
        let dst = dir.path().join("out.bin.enc");

        let key = random_key();
        let nonce = random_nonce();
        let mut enc = Encrypter::new();
        let result = enc.encrypt_file(&src_dir, &dst, &key, &nonce);
        assert!(result.is_err(), "encrypting a directory should fail");
        assert!(!dst.exists(), "partial output must be cleaned up");
    }

    #[test]
    fn rsa_encrypt_decrypt_key() {
        use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use std::borrow::BorrowMut;

        let bits = 2048;
        let private_key =
            RsaPrivateKey::new(&mut rand::rngs::OsRng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        // Round-trip through PEM like the real pipeline does.
        let pem = private_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        let private_key = RsaPrivateKey::from_pkcs1_pem(&pem).unwrap();

        let symmetric = [0x42u8; 32];
        let padding = rsa::Oaep::new::<sha2::Sha256>();
        let encrypted = public_key
            .encrypt(OsRng.borrow_mut(), padding, &symmetric)
            .unwrap();
        let padding = rsa::Oaep::new::<sha2::Sha256>();
        let decrypted = private_key.decrypt(padding, &encrypted).unwrap();
        assert_eq!(decrypted.as_slice(), &symmetric);
    }

    #[test]
    fn encrypted_path_helpers() {
        assert_eq!(
            encrypted_path(Path::new("dir/foo.txt")),
            std::path::PathBuf::from("dir/foo.txt.enc")
        );
        assert_eq!(
            decrypted_path(Path::new("dir/foo.txt.enc")).unwrap(),
            std::path::PathBuf::from("dir/foo.txt")
        );
        assert!(decrypted_path(Path::new("dir/foo.txt")).is_none());
        assert!(decrypted_path(Path::new(".enc")).is_none());
    }
}
