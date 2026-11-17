//! Paths reserved for the new WebUI-managed single-Agent/single-Mihomo runtime.
//! This root is deliberately disjoint from legacy cleanup candidates.

pub const MIHOMO_DIR: &str = "/data/u60-pro-managed/mihomo";
pub const MIHOMO_BINARY: &str = "/data/u60-pro-managed/mihomo/mihomo";
pub const MIHOMO_CONFIG: &str = "/data/u60-pro-managed/mihomo/config.yaml";
pub const MIHOMO_STAGED_CONFIG: &str = "/data/u60-pro-managed/mihomo/config.staged.yaml";
pub const MIHOMO_STATE: &str = "/data/u60-pro-managed/mihomo/manager.json";
pub const MIHOMO_PROVIDERS: &str = "/data/u60-pro-managed/mihomo/providers";
pub const MIHOMO_PROFILES: &str = "/data/u60-pro-managed/mihomo/profiles";
pub const MIHOMO_CN_LIST: &str = "/data/u60-pro-managed/mihomo/cn.list";
pub const MIHOMO_CONTROLLER_SOCKET: &str = "/data/u60-pro-managed/mihomo/mihomo.sock";
pub const MIHOMO_UI: &str = "/data/u60-pro-managed/mihomo/ui";
pub const MIHOMO_LOG: &str = "/data/u60-pro-managed/mihomo/mihomo.log";
pub const MIHOMO_PID: &str = "/data/u60-pro-managed/mihomo/mihomo.pid";

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn overlaps(left: &str, right: &str) -> bool {
        let left = Path::new(left);
        let right = Path::new(right);
        left == right || left.starts_with(right) || right.starts_with(left)
    }

    #[test]
    fn managed_paths_do_not_overlap_legacy_cleanup_targets() {
        let managed = [
            MIHOMO_DIR,
            MIHOMO_BINARY,
            MIHOMO_CONFIG,
            MIHOMO_STAGED_CONFIG,
            MIHOMO_STATE,
            MIHOMO_PROVIDERS,
            MIHOMO_PROFILES,
            MIHOMO_CN_LIST,
            MIHOMO_CONTROLLER_SOCKET,
            MIHOMO_UI,
            MIHOMO_LOG,
            MIHOMO_PID,
        ];
        let legacy = [
            "/data/zte-agent",
            "/data/local/tmp/start_zte_agent.sh",
            "/data/mihomo",
            "/var/run/mihomo.pid",
            "/tmp/mihomo.log",
            "/etc/rc.local",
        ];

        for runtime_path in managed {
            for cleanup_path in legacy {
                assert!(
                    !overlaps(runtime_path, cleanup_path),
                    "managed path {runtime_path} overlaps cleanup target {cleanup_path}"
                );
            }
        }
    }
}
