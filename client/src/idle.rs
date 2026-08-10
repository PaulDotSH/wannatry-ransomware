//! Optional gating of the encryption run on system idle time.
//!
//! Enabled with the `idle-gating` cargo feature. When disabled, [`IdleGate`]
//! is a no-op and the encryption behaves exactly as before.

use std::time::Duration;

/// Minimum system idle time (seconds) that must have elapsed before the
/// encryption run starts. Operator-set: raise this to wait for a longer
/// "away" window before kicking off.
pub const IDLE_THRESHOLD_SECS: u64 = 120;

/// When `true`, an in-flight run pauses while the user is active again (idle
/// time drops below the threshold) and resumes once they are idle again. Set
/// to `false` to run straight through once started.
pub const PAUSE_WHEN_NOT_AFK: bool = true;

/// How often to re-check idle time while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Shared gate consulted before a run and by each worker between files.
///
/// Stateless with respect to runtime input (all behavior is fixed at compile
/// time by the feature and the consts above), so a fresh gate anywhere behaves
/// identically.
#[derive(Clone, Copy, Debug)]
pub struct IdleGate {
    threshold: Duration,
    pause_when_active: bool,
}

impl Default for IdleGate {
    fn default() -> Self {
        Self::new()
    }
}

impl IdleGate {
    pub fn new() -> Self {
        IdleGate {
            threshold: Duration::from_secs(IDLE_THRESHOLD_SECS),
            pause_when_active: PAUSE_WHEN_NOT_AFK,
        }
    }

    /// Only start once the machine has been idle long enough. Blocks until the
    /// idle time is at least the threshold. No-op when `idle-gating` is off.
    pub fn wait_before_start(&self) {
        if cfg!(feature = "idle-gating") {
            wait_until_idle(self.threshold);
        }
    }

    /// Pause mid-run when the user becomes active again. Called by each worker
    /// before encrypting a file. No-op unless `idle-gating` is enabled and
    /// [`PAUSE_WHEN_NOT_AFK`] is true.
    pub fn pause_if_user_active(&self) {
        if cfg!(feature = "idle-gating") && self.pause_when_active {
            wait_until_idle(self.threshold);
        }
    }
}

fn wait_until_idle(threshold: Duration) {
    while idle_time() < threshold {
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Milliseconds since the last keyboard/mouse input on Windows.
#[cfg(all(windows, feature = "idle-gating"))]
fn idle_time() -> Duration {
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    unsafe {
        let mut last = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        if GetLastInputInfo(&mut last) == 0 {
            return Duration::ZERO;
        }
        let now = GetTickCount();
        Duration::from_millis(now.saturating_sub(last.dwTime) as u64)
    }
}

/// Stub for non-Windows builds or when `idle-gating` is disabled: always
/// reports "idle", so the gate never blocks.
#[cfg(not(all(windows, feature = "idle-gating")))]
fn idle_time() -> Duration {
    Duration::MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_reads_configured_constants() {
        let gate = IdleGate::new();
        assert_eq!(gate.threshold, Duration::from_secs(IDLE_THRESHOLD_SECS));
        assert_eq!(gate.pause_when_active, PAUSE_WHEN_NOT_AFK);
    }

    #[test]
    fn idle_time_returns_a_value() {
        let _ = idle_time();
    }
}
