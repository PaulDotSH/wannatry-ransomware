use std::borrow::BorrowMut;
use std::fs;
use std::fs::File;
use std::io::Read;

use anyhow::anyhow;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use rand::rngs::OsRng;
use rsa::pkcs1::LineEnding;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};

const DEFAULT_BITS: usize = 4096;

const USAGE: &str = "\
USAGE:
    decrypt [COMMAND] [ARGS]

COMMANDS:
    (default)         Decrypt key.part1 + key.part2 using priv.key and write decryption.key
    generate [BITS]   Generate a fresh RSA keypair (priv.key + pub.key), default 4096 bits
    help              Show this help

EXAMPLES:
    decrypt generate 4096
    decrypt
";

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        None | Some("decrypt") => decrypt(),
        Some("generate") => generate(parse_bits(&args)?),
        Some("help") | Some("-h") | Some("--help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(anyhow!("Unknown command: {other}\n\n{USAGE}")),
    }
}

fn parse_bits(args: &[String]) -> Result<usize, anyhow::Error> {
    match args.get(1) {
        None => Ok(DEFAULT_BITS),
        Some(bits) => bits
            .parse()
            .map_err(|err| anyhow!("Invalid key size '{bits}': {err}")),
    }
}

fn generate(bits: usize) -> Result<(), anyhow::Error> {
    let private_key = RsaPrivateKey::new(OsRng.borrow_mut(), bits)
        .map_err(|err| anyhow!("failed to generate a key: {err}"))?;

    let private_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|err| anyhow!("Failed to encode private key: {err}"))?;
    fs::write("priv.key", private_pem.as_bytes())
        .map_err(|err| anyhow!("Cannot write priv.key: {err}"))?;

    let public_key = RsaPublicKey::from(&private_key);
    let public_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|err| anyhow!("Failed to encode public key: {err}"))?;
    fs::write("pub.key", public_pem.as_bytes())
        .map_err(|err| anyhow!("Cannot write pub.key: {err}"))?;

    println!("Generated {bits}-bit RSA keypair: priv.key and pub.key");
    Ok(())
}

fn decrypt() -> Result<(), anyhow::Error> {
    let private_key_pem =
        fs::read_to_string("priv.key").map_err(|err| anyhow!("Cannot read priv.key: {err}"))?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem.as_str())
        .map_err(|err| anyhow!("Invalid priv.key: {err}"))?;

    let enc = fs::read("key.part1").map_err(|err| anyhow!("Cannot read key.part1: {err}"))?;

    let padding = Oaep::new::<sha2::Sha256>();
    let key_vec = private_key
        .decrypt(padding, enc.as_slice())
        .map_err(|err| anyhow!("failed to decrypt: {err}"))?;
    let key: [u8; 32] = key_vec
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("Wrong key size: expected 32 bytes, got {}", key_vec.len()))?;

    let mut nonce = [0u8; 24];
    let mut file = File::open("key.part2").map_err(|err| anyhow!("Cannot read key.part2: {err}"))?;
    file.read_exact(&mut nonce)
        .map_err(|err| anyhow!("Cannot read nonce: {err}"))?;

    let mut vec = Vec::new();
    file.read_to_end(&mut vec)
        .map_err(|err| anyhow!("Cannot read encrypted data: {err}"))?;

    let dec = decrypt_bytes(vec.as_slice(), &key)
        .map_err(|err| anyhow!("Cannot decrypt message: {err}"))?;
    println!("Decryption bytes - {:?}", &key);
    fs::write("decryption.key", &key).map_err(|err| anyhow!("Cannot write decryption key: {err}"))?;
    println!("{:?}", String::from_utf8(dec).map_err(|err| anyhow!("Malformed string was decrypted: {err}"))?);
    Ok(())
}

fn decrypt_bytes(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let dec = cipher
        .decrypt(data[0..24].into(), data[24..].as_ref())
        .map_err(|err| anyhow!("Decrypting bytes: {}", err))?;
    Ok(dec)
}
