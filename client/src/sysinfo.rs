use serde::{Deserialize, Serialize};
use sysinfo::{Disks, Networks, System, Users};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Debug, Zeroize)]
pub struct SysInfo {
    pub disks: String,
    pub all_memory: u64,
    pub boot_time: u64,
    pub cpus: String,
    pub distribution_id: String,
    pub cpu_info: String,
    pub host_name: Option<String>,
    pub kernel_version: Option<String>,
    pub os_version: Option<String>,
    pub name: Option<String>,
    pub networks: String,
    pub core_count: Option<usize>,
    pub swap_size: u64,
    pub uptime: u64,
    pub users: String,
}

impl SysInfo {
    pub fn new() -> Self {
        let sys = System::new_all();
        SysInfo {
            disks: format!("{:?}", Disks::new_with_refreshed_list()),
            all_memory: sys.available_memory(),
            boot_time: System::boot_time(),
            cpus: format!("{:?}", sys.cpus()),
            distribution_id: System::distribution_id(),
            cpu_info: format!("{:?}", sys.cpus()),
            host_name: System::host_name(),
            kernel_version: System::kernel_version(),
            os_version: System::long_os_version(),
            name: System::name(),
            networks: format!("{:?}", Networks::new_with_refreshed_list()),
            core_count: System::physical_core_count(),
            swap_size: sys.total_swap(),
            uptime: System::uptime(),
            users: format!("{:?}", Users::new_with_refreshed_list()),
        }
    }
}

impl Default for SysInfo {
    fn default() -> Self {
        Self::new()
    }
}
