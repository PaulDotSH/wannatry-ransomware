//! Network share enumeration (opt-in via the `net-shares` cargo feature).
//!
//! Discovers the filesystem roots a local-disk scan would miss:
//!
//! - **Windows** — mapped network drives and reachable UNC shares
//!   (`\\server\share`) via the WNet API.
//! - **Linux** — NFS/CIFS mount points parsed from `/proc/mounts`.
//!
//! The feature is off by default: [`discover_net_roots`] then returns an empty
//! list and the walker behaves exactly as before.

use std::path::PathBuf;

/// Network filesystem roots to walk in addition to local disks. Empty when the
/// feature is disabled or no shares are reachable.
///
/// The probe is cached: enumeration (especially the Windows UNC walk) can touch
/// the live network, so it runs at most once per process.
pub fn discover_net_roots() -> Vec<PathBuf> {
    #[cfg(feature = "net-shares")]
    {
        static NET_ROOTS: std::sync::OnceLock<Vec<PathBuf>> = std::sync::OnceLock::new();
        NET_ROOTS.get_or_init(compute_net_roots).clone()
    }
    #[cfg(not(feature = "net-shares"))]
    {
        Vec::new()
    }
}

#[cfg(feature = "net-shares")]
fn compute_net_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    #[cfg(windows)]
    push_windows_shares(&mut roots);
    #[cfg(all(unix, not(target_os = "macos")))]
    push_linux_mounts(&mut roots);
    roots
}

#[cfg(feature = "net-shares")]
fn push_unique(roots: &mut Vec<PathBuf>, root: PathBuf) {
    if !roots.contains(&root) {
        roots.push(root);
    }
}

// ---------------------------------------------------------------------------
// Linux: read the remote mount points out of /proc/mounts.
// ---------------------------------------------------------------------------

/// Filesystem types in `/proc/mounts` that point at remote shares.
/// Compiled on Unix (used by [`push_linux_mounts`]) and under test (the
/// parser is tested on every platform).
#[cfg(any(all(unix, not(target_os = "macos")), test))]
#[cfg(feature = "net-shares")]
const REMOTE_FS: &[&str] = &[
    "nfs", "nfs2", "nfs3", "nfs4", "cifs", "smb", "smb2", "smb3", "fuse.sshfs",
    "9p", "afp", "davfs",
];

#[cfg(all(unix, not(target_os = "macos"), feature = "net-shares"))]
fn push_linux_mounts(roots: &mut Vec<PathBuf>) {
    if let Ok(data) = std::fs::read_to_string("/proc/mounts") {
        for mount in parse_mounts(&data) {
            push_unique(roots, mount);
        }
    }
}

/// Parse a `/proc/mounts`-style listing into the mount points of remote
/// (network) filesystems. Split out from the file read so it can be tested
/// without a real mount table.
#[cfg(any(all(unix, not(target_os = "macos")), test))]
#[cfg(feature = "net-shares")]
fn parse_mounts(data: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for line in data.lines() {
        // Format: fs_spec fs_file fs_vfstype fs_mntopts fs_freq fs_passno
        let mut fields = line.split_whitespace();
        let _spec = fields.next();
        let mount = fields.next();
        let fstype = fields.next();
        if let (Some(mount), Some(fstype)) = (mount, fstype) {
            if REMOTE_FS.contains(&fstype) {
                out.push(PathBuf::from(unescape_mount(mount)));
            }
        }
    }
    out
}

/// Decode the octal escape sequences (`\040` = space, `\011` = tab,
/// `\012` = newline, `\134` = backslash) that `/proc/mounts` uses for
/// characters that would otherwise break its whitespace-split format.
#[cfg(any(all(unix, not(target_os = "macos")), test))]
#[cfg(feature = "net-shares")]
fn unescape_mount(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let oct = bytes[i + 1..i + 4].iter().all(|b| b.is_ascii_digit());
            if oct {
                let code = (bytes[i + 1] - b'0') * 64 + (bytes[i + 2] - b'0') * 8 + (bytes[i + 3] - b'0');
                out.push(code);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Windows: enumerate mapped drives and UNC shares with the WNet API.
// ---------------------------------------------------------------------------

#[cfg(all(windows, feature = "net-shares"))]
fn push_windows_shares(roots: &mut Vec<PathBuf>) {
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::NetworkManagement::WNet::{
        WNetCloseEnum, WNetEnumResourceW, WNetOpenEnumW, NETRESOURCEW,
        RESOURCE_CONNECTED, RESOURCE_GLOBALNET, RESOURCETYPE_DISK,
        RESOURCEUSAGE_CONNECTABLE, RESOURCEUSAGE_CONTAINER,
    };

    const INITIAL_BUF: usize = 16 * 1024;
    const MAX_BUF: usize = 1024 * 1024;
    /// Hard cap on container nesting. Real network namespaces are a few levels
    /// deep (domain -> server -> share); a deeper topology is treated as
    /// pathological and abandoned so enumeration can't recurse forever.
    const MAX_DEPTH: u32 = 8;

    /// Recursively walk one scope of the network namespace. A null `parent`
    /// starts at the top of `scope`.
    unsafe fn walk(
        scope: u32,
        usage: u32,
        parent: *const NETRESOURCEW,
        depth: u32,
        roots: &mut Vec<PathBuf>,
    ) {
        if depth > MAX_DEPTH {
            return;
        }

        let mut handle = std::ptr::null_mut();
        if WNetOpenEnumW(scope, RESOURCETYPE_DISK, usage, parent, &mut handle) != 0 {
            return;
        }

        let mut buf = vec![0u8; INITIAL_BUF];
        loop {
            let mut count = u32::MAX;
            let mut size = buf.len() as u32;
            let ret = WNetEnumResourceW(handle, &mut count, buf.as_mut_ptr() as *mut _, &mut size);
            if ret != 0 {
                // Buffer too small: grow and retry; anything else (including
                // ERROR_NO_MORE_ITEMS) ends this scope.
                if ret == ERROR_MORE_DATA && buf.len() < MAX_BUF {
                    buf.resize(buf.len() * 2, 0);
                    continue;
                }
                break;
            }

            let resources =
                std::slice::from_raw_parts(buf.as_ptr() as *const NETRESOURCEW, count as usize);
            for r in resources {
                if (r.dwUsage & RESOURCEUSAGE_CONTAINER) != 0 {
                    walk(scope, usage, r as *const NETRESOURCEW, depth + 1, roots);
                }
                if r.dwType == RESOURCETYPE_DISK {
                    if let Some(remote) = wide_string(r.lpRemoteName) {
                        if remote.starts_with(r"\\") {
                            push_unique(roots, PathBuf::from(remote));
                        }
                    }
                }
            }
        }

        WNetCloseEnum(handle);
    }

    unsafe {
        // Mapped drives first (cheap, always reachable): no network round
        // trips are needed, so do this synchronously.
        walk(RESOURCE_CONNECTED, 0, std::ptr::null(), 0, roots);

        // The UNC namespace is enumerated in a helper thread bounded by a hard
        // timeout. WNet's GLOBALNET scope walks the live network and can block
        // for a long time on unreachable hosts; a hung probe must never stall
        // the run, so whatever isn't found in time is simply skipped.
        const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        let (tx, rx) = std::sync::mpsc::channel::<Vec<PathBuf>>();
        std::thread::spawn(move || {
            let mut found = Vec::new();
            walk(
                RESOURCE_GLOBALNET,
                RESOURCEUSAGE_CONNECTABLE | RESOURCEUSAGE_CONTAINER,
                std::ptr::null(),
                0,
                &mut found,
            );
            let _ = tx.send(found);
        });
        if let Ok(found) = rx.recv_timeout(PROBE_TIMEOUT) {
            for root in found {
                push_unique(roots, root);
            }
        }
    }
}

/// Decode a NUL-terminated UTF-16 string.
#[cfg(all(windows, feature = "net-shares"))]
unsafe fn wide_string(p: windows_sys::core::PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *p.add(len) != 0 {
        len += 1;
    }
    Some(String::from_utf16_lossy(std::slice::from_raw_parts(p, len)))
}

#[cfg(all(test, feature = "net-shares"))]
mod tests {
    use super::*;

    #[test]
    fn parses_remote_mount_points() {
        let data = "\
tmpfs /run tmpfs rw,nosuid 0 0
/dev/sda1 / ext4 rw,relatime 0 0
192.168.1.10:/srv/data /mnt/nfs nfs4 rw,relatime 0 0
//SERVER/share /mnt/winshare cifs ro,guest 0 0
tmpfs /dev/shm tmpfs rw 0 0";
        let names: Vec<String> = parse_mounts(data)
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["/mnt/nfs".to_string(), "/mnt/winshare".to_string()]);
    }

    #[test]
    fn ignores_local_and_pseudo_filesystems() {
        let data = "\
/dev/sda1 / ext4 rw 0 0
proc /proc proc rw 0 0
sysfs /sys sysfs rw 0 0";
        assert!(parse_mounts(data).is_empty());
    }

    #[test]
    fn unescapes_octal_escapes() {
        assert_eq!(unescape_mount("/mnt/My\\040Share"), "/mnt/My Share");
        assert_eq!(unescape_mount("/mnt/plain"), "/mnt/plain");
    }
}
