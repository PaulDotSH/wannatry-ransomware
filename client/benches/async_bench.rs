// Benchmark: sync vs async (tokio) file-level encryption.
//
// Three scenarios:
//   - "multiple": a handful of medium files (8 MiB each)
//   - "lots_small": many tiny files (4-64 KiB)
//   - "existing_config": the mixed tree from the walker bench
//
// Variants per scenario:
//   - sync sequential          : Encrypter + std::fs, single thread
//   - sync rayon               : Encrypter + std::fs, rayon par_iter
//   - async tokio_fs           : streaming cipher over tokio::fs async I/O
//   - async spawn_blocking     : existing Encrypter wrapped in spawn_blocking

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::KeyInit;
use client_lib::crypto::{self, Encrypter, KEY_LEN, STREAM_NONCE_LEN};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::rngs::OsRng;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BUF: usize = 256 * 1024; // matches DEFAULT_BUFFER_LEN

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

fn build_tree(root: &Path, small: usize, medium: usize, large: usize, huge: usize) -> Vec<PathBuf> {
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
        std::fs::write(&p, vec![0x22u8; 8 << 20]).unwrap();
        paths.push(p);
    }
    for i in 0..large {
        let p = root.join(format!("large/file_{:04}.dat", i));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![0x33u8; 64 << 20]).unwrap();
        paths.push(p);
    }
    for i in 0..huge {
        let p = root.join(format!("huge/file_{:04}.dat", i));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![0x44u8; 300 << 20]).unwrap();
        paths.push(p);
    }
    paths
}

fn encrypt_sync_file(path: &Path, key: &[u8; KEY_LEN]) -> bool {
    let mut enc = Encrypter::new();
    let mut nonce = random_nonce();
    OsRng.fill_bytes(&mut nonce);
    let dst = crypto::encrypted_path(path);
    enc.encrypt_file(path, &dst, key, &nonce).is_ok()
}

fn encrypt_sync_sequential(paths: &[PathBuf], key: &[u8; KEY_LEN]) -> u64 {
    paths.iter().map(|p| u64::from(encrypt_sync_file(p, key))).sum()
}

fn encrypt_sync_rayon(paths: &[PathBuf], key: &[u8; KEY_LEN]) -> u64 {
    use rayon::prelude::*;
    paths.par_iter().map(|p| u64::from(encrypt_sync_file(p, key))).sum()
}

/// Streaming cipher driven by tokio::fs async I/O, one task per file,
/// concurrency bounded by `limit`.
async fn encrypt_async_fs(paths: Vec<PathBuf>, key: [u8; KEY_LEN], limit: usize) -> u64 {
    use tokio::task::JoinSet;
    let mut set = JoinSet::new();
    let sem = Arc::new(tokio::sync::Semaphore::new(limit));
    let mut count = 0u64;

    for p in paths {
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let key = key;
        set.spawn(async move {
            let _permit = permit;
            let mut nonce = random_nonce();
            OsRng.fill_bytes(&mut nonce);
            let aead = chacha20poly1305::XChaCha20Poly1305::new(key.as_ref().into());
            let mut enc =
                chacha20poly1305::aead::stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());
            let dst = crypto::encrypted_path(&p);
            let mut src = match tokio::fs::File::open(&p).await {
                Ok(f) => f,
                Err(_) => return 0u64,
            };
            let mut out = match tokio::fs::File::create(&dst).await {
                Ok(f) => f,
                Err(_) => return 0u64,
            };
            if out.write_all(&nonce).await.is_err() {
                return 0u64;
            }
            let mut buf = vec![0u8; BUF];
            loop {
                let n = match src.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => {
                        let _ = std::fs::remove_file(&dst);
                        return 0u64;
                    }
                };
                if n == buf.len() {
                    match enc.encrypt_next(&buf[..n]) {
                        Ok(ct) => {
                            if out.write_all(&ct).await.is_err() {
                                let _ = std::fs::remove_file(&dst);
                                return 0u64;
                            }
                        }
                        Err(_) => {
                            let _ = std::fs::remove_file(&dst);
                            return 0u64;
                        }
                    }
                } else {
                    match enc.encrypt_last(&buf[..n]) {
                        Ok(ct) => {
                            if out.write_all(&ct).await.is_err() {
                                let _ = std::fs::remove_file(&dst);
                                return 0u64;
                            }
                        }
                        Err(_) => {
                            let _ = std::fs::remove_file(&dst);
                            return 0u64;
                        }
                    }
                    break;
                }
            }
            1u64
        });
    }
    while let Some(res) = set.join_next().await {
        count += res.unwrap_or(0);
    }
    count
}

/// Existing blocking Encrypter wrapped in `spawn_blocking`.
async fn encrypt_spawn_blocking(paths: Vec<PathBuf>, key: [u8; KEY_LEN], limit: usize) -> u64 {
    use tokio::task::JoinSet;
    let mut set = JoinSet::new();
    let sem = Arc::new(tokio::sync::Semaphore::new(limit));
    let mut count = 0u64;

    for p in paths {
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let key = key;
        set.spawn(async move {
            let _permit = permit;
            tokio::task::spawn_blocking(move || u64::from(encrypt_sync_file(&p, &key)))
                .await
                .unwrap_or(0)
        });
    }
    while let Some(res) = set.join_next().await {
        count += res.unwrap_or(0);
    }
    count
}

/// Hybrid: route by file size. Files >= `threshold` bytes go through a tokio
/// `spawn_blocking` pool (the winning strategy for few-large-file workloads);
/// smaller files go through a dedicated rayon pool (the winner on many-small
/// / mixed workloads). Both run concurrently so large I/O never starves the
/// small-file stream and vice-versa.
fn encrypt_hybrid(
    paths: Vec<PathBuf>,
    key: [u8; KEY_LEN],
    threshold: u64,
    big_workers: usize,
    small_workers: usize,
) -> u64 {
    let (big, small): (Vec<PathBuf>, Vec<PathBuf>) = paths.into_iter().partition(|p| {
        std::fs::metadata(p).map(|m| m.len()).unwrap_or(0) >= threshold
    });

    let small_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(small_workers)
        .build()
        .unwrap();
    let small_handle = std::thread::spawn(move || small_pool.install(|| encrypt_sync_rayon(&small, &key)));

    let big_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(big_workers)
        .enable_all()
        .build()
        .unwrap();
    let big_count = big_rt.block_on(encrypt_spawn_blocking(big, key, big_workers));
    let small_count = small_handle.join().unwrap();

    big_count + small_count
}

fn bench_async(c: &mut Criterion) {
    let mut group = c.benchmark_group("sync_vs_async");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    let key = random_key();
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).max(1);

    // Scenarios split by file size so both "fast on big" and "fast on many
    // small" are measured separately, plus a genuine mix of both.
    let scenarios: Vec<(&str, (usize, usize, usize, usize))> = vec![
        ("big_only", (0, 0, 6, 0)),          // 6 x 64 MiB
        ("huge_only", (0, 0, 0, 5)),         // 5 x 300 MiB
        ("small_only", (2000, 0, 0, 0)),     // 2000 x 4-64 KiB
        ("mixed", (500, 20, 3, 2)),          // both sizes, closer to real tree
    ];

    for (name, (small, medium, large, huge)) in scenarios {
        let dir = TempDir::new().unwrap();
        let paths = build_tree(dir.path(), small, medium, large, huge);
        let n = paths.len() as u64;
        group.throughput(Throughput::Elements(n));

        group.bench_with_input(BenchmarkId::new(name, "sync_sequential"), &paths, |b, paths| {
            b.iter(|| {
                let _ = encrypt_sync_sequential(paths, &key);
            })
        });
        group.bench_with_input(BenchmarkId::new(name, "sync_rayon"), &paths, |b, paths| {
            b.iter(|| {
                let _ = encrypt_sync_rayon(paths, &key);
            })
        });
        group.bench_with_input(BenchmarkId::new(name, "async_tokio_fs"), &paths, |b, paths| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            b.iter(|| {
                let paths = paths.clone();
                rt.block_on(async {
                    let _ = encrypt_async_fs(paths, key, cores).await;
                });
            })
        });
        group.bench_with_input(BenchmarkId::new(name, "async_spawn_blocking"), &paths, |b, paths| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            b.iter(|| {
                let paths = paths.clone();
                rt.block_on(async {
                    let _ = encrypt_spawn_blocking(paths, key, cores).await;
                });
            })
        });
        group.bench_with_input(BenchmarkId::new(name, "hybrid"), &paths, |b, paths| {
            b.iter(|| {
                // big workers for the spawn_blocking pool, rest for rayon
                let big_workers = (cores / 2).max(1);
                let small_workers = (cores - big_workers).max(1);
                let paths = paths.clone();
                let _ = encrypt_hybrid(paths, key, 1 << 20, big_workers, small_workers);
            })
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5));
    targets = bench_async
}
criterion_main!(benches);
