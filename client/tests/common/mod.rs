//! Shared helpers for integration tests.

use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::rand_core::RngCore;
use rand::rngs::OsRng;
use tempfile::TempDir;

/// A small, deterministic fixture tree stored in a temp dir.
/// Returns `(TempDir, Vec<(relative_path, content)>)`.
pub fn make_small_fixture_tree() -> (TempDir, Vec<(PathBuf, Vec<u8>)>) {
    let dir = TempDir::new().unwrap();
    let mut files = Vec::new();

    let specs = [
        ("Documents/report.md", b"# quarterly report\nsome body text".as_slice()),
        ("Documents/notes.txt", b"plain notes".as_slice()),
        ("Documents/data.json", br#"{"a":1,"b":2}"#),
        ("Documents/spreadsheet.csv", b"a,b,c\n1,2,3".as_slice()),
        ("Pictures/photo.png", b"\x89PNG\r\n\x1a\nfakepng".as_slice()),
        ("Pictures/photo.jpg", b"fakepjpeg".as_slice()),
        ("Pictures/vector.svg", b"<svg xmlns='x'/>".as_slice()),
        ("Downloads/archive.zip", b"PK\x03\x04 fake zip".as_slice()),
        ("Downloads/ebook.pdf", b"%PDF-1.4 fake".as_slice()),
        ("Desktop/misc/readme.txt", b"read me".as_slice()),
        ("Desktop/misc/config.env", b"KEY=VALUE".as_slice()),
    ];

    for (rel, content) in specs {
        let p = dir.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, content).unwrap();
        files.push((PathBuf::from(rel), content.to_vec()));
    }

    (dir, files)
}

pub fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn assert_tree_contents_equal(root: &Path, expected: &[(PathBuf, Vec<u8>)]) {
    for (rel, content) in expected {
        let got = fs::read(root.join(rel)).unwrap_or_else(|e| panic!("missing {:?}: {}", rel, e));
        assert_eq!(&got, content, "content mismatch for {:?}", rel);
    }
}
