use log::{error, info};
use self_update::cargo_crate_version;

/// 把編譯期的平台資訊對應到 GitHub Release 的資產命名。
///
/// Release 資產命名規則(見 `.github/workflows/release.yml`):
///   `taiwanfrp-<os>-<arch>-<tag>[.exe]`
/// 例如 `taiwanfrp-linux-amd64-v0.1.0`、`taiwanfrp-windows-amd64-v0.1.0.exe`。
fn asset_target() -> Option<String> {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        return None;
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "arm") {
        "arm32"
    } else {
        return None;
    };

    Some(format!("{os}-{arch}"))
}

/// 檢查 GitHub Release 是否有更新版本,若有則下載並原地替換目前執行檔。
pub fn run_update() -> Result<(), Box<dyn std::error::Error>> {
    let target = asset_target().ok_or("unsupported platform for self-update")?;

    let status = self_update::backends::github::Update::configure()
        .repo_owner("redbean0721")
        .repo_name("agent")
        .bin_name("taiwanfrp")
        // 以 "<os>-<arch>" 子字串比對資產,避免誤中其他平台
        .target(&target)
        .show_download_progress(true)
        .current_version(cargo_crate_version!())
        .build()?
        .update()?;

    if status.is_updated() {
        info!("Updated to {}", status.version());
    } else {
        info!("Already up to date ({})", status.version());
    }

    Ok(())
}

/// 包一層錯誤處理,供 `main` 直接呼叫。
pub fn update_and_exit() -> ! {
    match run_update() {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            error!("Update failed: {e}");
            std::process::exit(1);
        }
    }
}
