// Benchmark: tree traversal (walkdir vs jwalk) and file-level parallelism
// (sequential vs rayon vs channel-based threadpool at varying worker counts and
// channel capacities).
//
// Uses a synthetic fixture tree generated in a temp dir so the bench is
// self-contained. Set FIXTURES_DIR to point at a real generated tree.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use chacha20poly1305::aead::rand_core::RngCore;
use client_lib::crypto::{self, Encrypter, KEY_LEN, STREAM_NONCE_LEN};
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

/// Build a synthetic tree of `small`+`medium`+`large` files.
fn build_tree(root: &Path, small: usize, medium: usize, large: usize) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for i in 0..small {
        let p = root.join(format!("small/file_{:04}.dat", i));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![0x11u8; 4096 + (i % 7) * 1024]).unwrap();
        paths.push(p);
    }
    for i in 0..medium {
        let p = root.join(format!("medium/file_{:04}.dat", i));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![0x22u8; (1 + (i % 3)) << 20]).unwrap();
        paths.push(p);
    }
    for i in 0..large {
        let p = root.join(format!("large/file_{:04}.dat", i));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![0x33u8; 8 << 20]).unwrap();
        paths.push(p);
    }
    paths
}

fn encrypt_single(path: &Path, key: &[u8; KEY_LEN]) -> bool {
    let mut enc = Encrypter::new();
    let mut nonce = random_nonce();
    OsRng.fill_bytes(&mut nonce);
    let dst = crypto::encrypted_path(path);
    enc.encrypt_file(path, &dst, key, &nonce).is_ok()
}

/// Sequential: one Encrypter, one thread, files in order.
fn encrypt_sequential(paths: &[PathBuf], key: &[u8; KEY_LEN]) -> u64 {
    paths
        .iter()
        .map(|p| u64::from(encrypt_single(p, key)))
        .sum()
}

/// Rayon par_iter over files.
fn encrypt_rayon(paths: &[PathBuf], key: &[u8; KEY_LEN]) -> u64 {
    use rayon::prelude::*;
    paths
        .par_iter()
        .map(|p| u64::from(encrypt_single(p, key)))
        .sum()
}

/// Rayon par_iter with a per-worker reused Encrypter (`map_init`): each worker
/// allocates its buffers once and reuses them across every file it handles,
/// instead of a fresh ~512 KiB allocation per file.
fn encrypt_rayon_reuse(paths: &[PathBuf], key: &[u8; KEY_LEN]) -> u64 {
    use rayon::prelude::*;
    paths
        .par_iter()
        .map_init(
            || Encrypter::new(),
            |enc, p| {
                let mut nonce = random_nonce();
                OsRng.fill_bytes(&mut nonce);
                let dst = crypto::encrypted_path(p);
                u64::from(enc.encrypt_file(p, &dst, key, &nonce).is_ok())
            },
        )
        .sum()
}

/// Channel-based threadpool: one producer feeding `workers` consumers through a
/// bounded channel of `capacity` slots (0 = unbounded).
fn encrypt_pipelined(paths: Vec<PathBuf>, key: [u8; KEY_LEN], workers: usize, capacity: usize) -> u64 {
    use std::sync::mpsc::SyncSender;

    enum Sender {
        Unbounded(std::sync::mpsc::Sender<PathBuf>),
        Bounded(SyncSender<PathBuf>),
    }
    impl Sender {
        fn send(&self, p: PathBuf) -> Result<(), ()> {
            match self {
                Sender::Unbounded(s) => s.send(p).map_err(|_| ()),
                Sender::Bounded(s) => s.send(p).map_err(|_| ()),
            }
        }
    }

    let (sender, rx) = match capacity {
        0 => {
            let (t, r) = mpsc::channel::<PathBuf>();
            (Sender::Unbounded(t), r)
        }
        n => {
            let (t, r) = mpsc::sync_channel::<PathBuf>(n);
            (Sender::Bounded(t), r)
        }
    };
    let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));

    let producer = std::thread::spawn(move || {
        for p in paths {
            if sender.send(p).is_err() {
                break;
            }
        }
    });

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let rx = std::sync::Arc::clone(&rx);
        let key = key;
        handles.push(std::thread::spawn(move || {
            let mut enc = Encrypter::new();
            let mut count = 0u64;
            loop {
                let item = rx.lock().unwrap().recv();
                match item {
                    Ok(p) => {
                        let mut nonce = random_nonce();
                        OsRng.fill_bytes(&mut nonce);
                        let dst = crypto::encrypted_path(&p);
                        if enc.encrypt_file(&p, &dst, &key, &nonce).is_ok() {
                            count += 1;
                        }
                    }
                    Err(_) => break,
                }
            }
            count
        }));
    }
    drop(rx);

    producer.join().unwrap();
    handles.into_iter().map(|h| h.join().unwrap()).sum()
}

fn bench_sequential_vs_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("sequential_vs_parallel");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    let key = random_key();
    let dir = TempDir::new().unwrap();
    let paths = build_tree(dir.path(), 400, 40, 10);
    let n = paths.len() as u64;
    group.throughput(Throughput::Elements(n));

    group.bench_function("sequential", |b| {
        b.iter(|| {
            let _ = encrypt_sequential(&paths, &key);
        })
    });
    group.bench_function("rayon_par_iter", |b| {
        b.iter(|| {
            let _ = encrypt_rayon(&paths, &key);
        })
    });
    group.bench_function("rayon_reuse_encrypter", |b| {
        b.iter(|| {
            let _ = encrypt_rayon_reuse(&paths, &key);
        })
    });
    group.bench_function("pipelined_4_workers", |b| {
        b.iter(|| {
            let _ = encrypt_pipelined(paths.clone(), key, 4, 256);
        })
    });
    group.finish();
}

fn bench_thread_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("thread_count");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    let key = random_key();
    let dir = TempDir::new().unwrap();
    let paths = build_tree(dir.path(), 400, 40, 10);
    let n = paths.len() as u64;
    group.throughput(Throughput::Elements(n));

    for workers in [1usize, 2, 4, 8, 16] {
        group.bench_with_input(BenchmarkId::from_parameter(workers), &workers, |b, &workers| {
            b.iter(|| {
                let _ = encrypt_pipelined(paths.clone(), key, workers, 256);
            })
        });
    }
    group.finish();
}

fn bench_channel_capacity(c: &mut Criterion) {
    let mut group = c.benchmark_group("channel_capacity");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    let key = random_key();
    let dir = TempDir::new().unwrap();
    let paths = build_tree(dir.path(), 400, 40, 10);
    let n = paths.len() as u64;
    group.throughput(Throughput::Elements(n));

    for capacity in [0usize, 64, 256, 1024] {
        group.bench_with_input(BenchmarkId::from_parameter(capacity), &capacity, |b, &capacity| {
            b.iter(|| {
                let _ = encrypt_pipelined(paths.clone(), key, 4, capacity);
            })
        });
    }
    group.finish();
}

fn walkdir_count(root: &Path) -> u64 {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count() as u64
}

fn jwalk_count(root: &Path) -> u64 {
    jwalk::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count() as u64
}

fn bench_walkdir_vs_jwalk(c: &mut Criterion) {
    let mut group = c.benchmark_group("walkdir_vs_jwalk");
    group.measurement_time(Duration::from_secs(3));
    group.sample_size(10);

    let dir = TempDir::new().unwrap();
    build_tree(dir.path(), 400, 40, 10);

    group.bench_function("walkdir", |b| {
        b.iter(|| {
            let _ = walkdir_count(dir.path());
        })
    });
    group.bench_function("jwalk", |b| {
        b.iter(|| {
            let _ = jwalk_count(dir.path());
        })
    });
    group.finish();
}

fn bench_all(c: &mut Criterion) {
    bench_sequential_vs_parallel(c);
    bench_thread_count(c);
    bench_channel_capacity(c);
    bench_walkdir_vs_jwalk(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5));
    targets = bench_all
}
criterion_main!(benches);
