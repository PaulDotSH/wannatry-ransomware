// Benchmark: streaming vs whole-file encryption, buffer sizes, memmap vs read.
//
// Fixture generation is intentionally lightweight here (single in-memory / temp
// files) so the bench focuses on the encryption strategy, not fixture I/O.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::KeyInit;
use client_lib::crypto::{
    self, Encrypter, DEFAULT_BUFFER_LEN, KEY_LEN, PREALLOC_MAX_LEN, STREAM_NONCE_LEN,
    WHOLE_FILE_THRESHOLD,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::rngs::OsRng;
use tempfile::TempDir;

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

/// Write a file of `size` bytes with cheap, non-random content.
fn make_file(dir: &Path, name: &str, size: usize) -> PathBuf {
    let path = dir.join(name);
    let mut f = fs::File::create(&path).unwrap();
    let chunk = vec![0xABu8; 1 << 20];
    let mut remaining = size;
    while remaining > 0 {
        let n = remaining.min(chunk.len());
        f.write_all(&chunk[..n]).unwrap();
        remaining -= n;
    }
    path
}

/// "Whole-file" strategy: read the entire file into memory, then encrypt the
/// buffer as a single stream operation (single `encrypt_last`).
fn encrypt_whole_file(src: &Path, dst: &Path, key: &[u8; KEY_LEN], nonce: &[u8; STREAM_NONCE_LEN]) {
    let data = fs::read(src).unwrap();
    let aead = chacha20poly1305::XChaCha20Poly1305::new(key.as_ref().into());
    let enc = chacha20poly1305::aead::stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());
    let ct = enc.encrypt_last(&*data).unwrap();
    let mut out = fs::File::create(dst).unwrap();
    out.write_all(nonce).unwrap();
    out.write_all(&ct).unwrap();
}

/// "Whole-file" strategy via the non-streaming AEAD (XChaCha20Poly1305::encrypt).
fn encrypt_whole_file_aead(src: &Path, dst: &Path, key: &[u8; KEY_LEN]) {
    let data = fs::read(src).unwrap();
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let blob = crypto::encrypt_bytes(&data, key, &nonce).unwrap();
    fs::write(dst, blob).unwrap();
}

fn bench_stream_vs_wholefile(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_vs_wholefile");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    let key = random_key();
    let nonce = random_nonce();

    for size in [64 * 1024, 1 << 20, 8 << 20, 64 << 20, 128 << 20, 256 << 20] {
        let dir = TempDir::new().unwrap();
        let src = make_file(dir.path(), "src.bin", size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("streaming", size), &size, |b, _| {
            b.iter_batched(
                || dir.path().join("out_stream.enc"),
                |dst| {
                    let mut enc = Encrypter::new();
                    enc.encrypt_file(&src, &dst, &key, &nonce).unwrap();
                    let _ = fs::remove_file(&dst);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("whole_file", size), &size, |b, _| {
            b.iter_batched(
                || dir.path().join("out_whole.enc"),
                |dst| {
                    encrypt_whole_file(&src, &dst, &key, &nonce);
                    let _ = fs::remove_file(&dst);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("whole_file_aead", size), &size, |b, _| {
            b.iter_batched(
                || dir.path().join("out_whole_aead.enc"),
                |dst| {
                    encrypt_whole_file_aead(&src, &dst, &key);
                    let _ = fs::remove_file(&dst);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_buffer_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_size");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    let key = random_key();
    let nonce = random_nonce();
    let dir = TempDir::new().unwrap();
    let src = make_file(dir.path(), "mix.bin", 256 << 20); // 256MB file
    group.throughput(Throughput::Bytes(256 << 20));

    for buf in [
        64 * 1024,
        256 * 1024,
        1 << 20,
        5 << 20,
        16 << 20,
        32 << 20,
        64 << 20,
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(buf), &buf, |b, &buf| {
            b.iter_batched(
                || dir.path().join("out_buf.enc"),
                |dst| {
                    let mut enc = Encrypter::with_buffer_len(buf);
                    enc.encrypt_file(&src, &dst, &key, &nonce).unwrap();
                    let _ = fs::remove_file(&dst);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_memmap_vs_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("memmap_vs_read");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    let key = random_key();
    let nonce = random_nonce();

    for size in [1 << 20, 8 << 20] {
        let dir = TempDir::new().unwrap();
        let src = make_file(dir.path(), "mem.bin", size);
        group.throughput(Throughput::Bytes(size as u64));

        // std::fs::read into memory, then stream-encrypt the slice.
        group.bench_with_input(BenchmarkId::new("std_read", size), &size, |b, _| {
            b.iter_batched(
                || dir.path().join("out_read.enc"),
                |dst| {
                    let data = fs::read(&src).unwrap();
                    let mut out = fs::File::create(&dst).unwrap();
                    let aead = chacha20poly1305::XChaCha20Poly1305::new(key.as_ref().into());
                    let enc =
                        chacha20poly1305::aead::stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());
                    let ct = enc.encrypt_last(&*data).unwrap();
                    out.write_all(&nonce).unwrap();
                    out.write_all(&ct).unwrap();
                    let _ = fs::remove_file(&dst);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        // memmap2 + streaming chunks from the mapped slice.
        group.bench_with_input(BenchmarkId::new("memmap", size), &size, |b, _| {
            b.iter_batched(
                || dir.path().join("out_mmap.enc"),
                |dst| {
                    let file = fs::File::open(&src).unwrap();
                    let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
                    let mut out = fs::File::create(&dst).unwrap();
                    out.write_all(&nonce).unwrap();
                    let aead = chacha20poly1305::XChaCha20Poly1305::new(key.as_ref().into());
                    let mut enc =
                        chacha20poly1305::aead::stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());
                    for chunk in mmap.chunks(1 << 20) {
                        let ct = enc.encrypt_next(chunk).unwrap();
                        out.write_all(&ct).unwrap();
                    }
                    let ct = enc.encrypt_last(&[][..]).unwrap();
                    out.write_all(&ct).unwrap();
                    let _ = fs::remove_file(&dst);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Find the largest file size where whole-file encryption still beats
/// streaming. Fine-grained sweep from 1 MiB to 32 MiB, where the crossover
/// from the coarse bench lives (between 1 MiB and 8 MiB).
fn bench_wholefile_crossover(c: &mut Criterion) {
    let mut group = c.benchmark_group("wholefile_crossover");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    let key = random_key();
    let nonce = random_nonce();

    for size in [
        1 << 20,
        2 << 20,
        4 << 20,
        6 << 20,
        8 << 20,
        12 << 20,
        16 << 20,
        24 << 20,
        32 << 20,
    ] {
        let dir = TempDir::new().unwrap();
        let src = make_file(dir.path(), "src.bin", size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("streaming", size), &size, |b, _| {
            b.iter_batched(
                || dir.path().join("out_stream.enc"),
                |dst| {
                    let mut enc = Encrypter::new();
                    enc.encrypt_file(&src, &dst, &key, &nonce).unwrap();
                    let _ = fs::remove_file(&dst);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("whole_file", size), &size, |b, _| {
            b.iter_batched(
                || dir.path().join("out_whole.enc"),
                |dst| {
                    encrypt_whole_file(&src, &dst, &key, &nonce);
                    let _ = fs::remove_file(&dst);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("whole_file_aead", size), &size, |b, _| {
            b.iter_batched(
                || dir.path().join("out_whole_aead.enc"),
                |dst| {
                    encrypt_whole_file_aead(&src, &dst, &key);
                    let _ = fs::remove_file(&dst);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Isolate the raw cost of constructing an `Encrypter` (two ~256 KiB heap
/// buffers) vs reusing one — no filesystem I/O, so this is a clean signal the
/// file-level benches drown in noise.
fn bench_encrypter_alloc(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypter_alloc");
    group.measurement_time(Duration::from_secs(3));
    group.sample_size(10);

    group.bench_function("fresh_per_iter", |b| {
        b.iter(|| {
            let mut total = 0usize;
            for _ in 0..10_000 {
                let enc = Encrypter::new();
                total = total.wrapping_add(enc.buffer_len);
                std::hint::black_box(total);
            }
        })
    });

    group.bench_function("reused", |b| {
        b.iter(|| {
            let enc = Encrypter::new();
            let mut total = 0usize;
            for _ in 0..10_000 {
                total = total.wrapping_add(enc.buffer_len);
                std::hint::black_box(total);
            }
        })
    });
    group.finish();
}

/// Mirror of `Encrypter::encrypt_file`'s strategy (whole-file <= 8 MiB,
/// 256 KiB streaming loop above it), but the output file is preallocated to
/// its exact final size with `set_len` before the first write. Final size is
/// `nonce(19) + plaintext + 16 bytes of AEAD tag per stream message`.
fn encrypt_prealloc(src: &Path, dst: &Path, key: &[u8; KEY_LEN], nonce: &[u8; STREAM_NONCE_LEN]) {
    let aead = chacha20poly1305::XChaCha20Poly1305::new(key.as_ref().into());
    let mut enc =
        chacha20poly1305::aead::stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let src_len = fs::metadata(src).unwrap().len();
    let mut out = fs::File::create(dst).unwrap();
    if src_len <= WHOLE_FILE_THRESHOLD {
        // Single whole-file message.
        out.set_len(src_len + STREAM_NONCE_LEN as u64 + 16).unwrap();
    } else if src_len <= PREALLOC_MAX_LEN {
        // One message per buffer-sized chunk plus a final (possibly empty) one.
        let messages = src_len / DEFAULT_BUFFER_LEN as u64 + 1;
        out.set_len(src_len + STREAM_NONCE_LEN as u64 + 16 * messages)
            .unwrap();
    }
    out.write_all(nonce).unwrap();

    if src_len <= WHOLE_FILE_THRESHOLD {
        let data = fs::read(src).unwrap();
        let ct = enc.encrypt_last(&*data).unwrap();
        out.write_all(&ct).unwrap();
        return;
    }

    let mut buf = vec![0u8; DEFAULT_BUFFER_LEN];
    let mut src_file = fs::File::open(src).unwrap();
    loop {
        let n = src_file.read(&mut buf).unwrap();
        if n == buf.len() {
            let ct = enc.encrypt_next(&buf[..n]).unwrap();
            out.write_all(&ct).unwrap();
        } else {
            let ct = enc.encrypt_last(&buf[..n]).unwrap();
            out.write_all(&ct).unwrap();
            break;
        }
    }
}

fn bench_preallocate(c: &mut Criterion) {
    let mut group = c.benchmark_group("preallocate");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    let key = random_key();
    let nonce = random_nonce();

    for size in [64 * 1024, 1 << 20, 8 << 20, 64 << 20, 256 << 20] {
        let dir = TempDir::new().unwrap();
        let src = make_file(dir.path(), "src.bin", size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("default", size), &size, |b, _| {
            b.iter_batched(
                || dir.path().join("out_default.enc"),
                |dst| {
                    let mut enc = Encrypter::new();
                    enc.encrypt_file(&src, &dst, &key, &nonce).unwrap();
                    let _ = fs::remove_file(&dst);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("prealloc", size), &size, |b, _| {
            b.iter_batched(
                || dir.path().join("out_prealloc.enc"),
                |dst| {
                    encrypt_prealloc(&src, &dst, &key, &nonce);
                    let _ = fs::remove_file(&dst);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_all(c: &mut Criterion) {
    bench_stream_vs_wholefile(c);
    bench_buffer_size(c);
    bench_memmap_vs_read(c);
    bench_wholefile_crossover(c);
    bench_encrypter_alloc(c);
    bench_preallocate(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5));
    targets = bench_all
}
criterion_main!(benches);
