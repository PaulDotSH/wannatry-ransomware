//! Keep the system awake during a run (opt-in via the `pressure` cargo
//! feature on Windows).
//!
//! Prevents sleep/hibernation mid-run so a partially-encrypted machine can't
//! drop to sleep and stall the job. Off by default: [`hold_awake`] returns
//! `None` and the run behaves exactly as before.

use std::marker::PhantomData;

/// Releases the awake-hold when dropped, so the machine can sleep again.
pub struct AwakeGuard(PhantomData<()>);

/// Hold the system awake for as long as the returned guard is alive.
pub fn hold_awake() -> Option<AwakeGuard> {
    #[cfg(all(windows, feature = "pressure"))]
    {
        unsafe {
            use windows_sys::Win32::System::Power::{
                SetThreadExecutionState, ES_AWAYMODE_REQUIRED, ES_CONTINUOUS, ES_SYSTEM_REQUIRED,
            };
            SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
        }
        Some(AwakeGuard(PhantomData))
    }
    #[cfg(not(all(windows, feature = "pressure")))]
    {
        None
    }
}

impl Drop for AwakeGuard {
    fn drop(&mut self) {
        #[cfg(all(windows, feature = "pressure"))]
        unsafe {
            use windows_sys::Win32::System::Power::{SetThreadExecutionState, ES_CONTINUOUS};
            SetThreadExecutionState(ES_CONTINUOUS);
        }
    }
}
