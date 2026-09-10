mod credentials;
mod i18n;
mod language;

use clap::Parser;
use colored::Colorize;
use reqwest::blocking::Client;
use sha2::Digest;
use std::io::{self, Cursor, Read, Write};
use zip::ZipArchive;

#[derive(Parser)]
#[command(version)]
#[command(before_help = "TaiwanFRP Agent", about)]
struct Cli {
    /// Show the system language
    #[arg(long)]
    lang: bool,
}

fn main() {
    let cli = Cli::parse();

    let language = language::get_system_locale();

    if cli.lang {
        println!("{}", language);
        return;
    }

    let i18n = i18n::load_language(&language);

    println!("{}", i18n.get("welcome"));

    match credentials::load_credentials() {
        Ok((username, password)) => {
            println!("{}", i18n.get("auth.credentials_found"));
            println!("{}{}", i18n.get("auth.username"), username);
            println!("{}{}", i18n.get("auth.password"), password);
        }

        Err(_) => {
            println!("{}", i18n.get("auth.credentials_not_found").yellow());

            print!("{}", i18n.get("auth.username"));
            io::stdout().flush().unwrap();

            let mut username = String::new();
            io::stdin().read_line(&mut username).unwrap();
            let username = username.trim();

            print!("{}", i18n.get("auth.password"));
            io::stdout().flush().unwrap();

            let password = rpassword::read_password().unwrap();

            credentials::save_credentials(username, &password).expect("Failed to save credentials");
            println!("{}", i18n.get("auth.credentials_saved"));
        }
    }

    let url =
        "https://github.com/fatedier/frp/releases/download/v0.63.0/frp_0.63.0_windows_amd64.zip";
    const FRP_SHA256: &str = "d76af76641ecc64719820f9f81a3eec6b76ad9f8ab43458eb8cd98554201f771";
    let client = Client::builder()
        .user_agent("TaiwanFRP-Agent/1.0")
        .build()
        .unwrap();
    println!("正在下載 frp 至記憶體中...");
    let response = client.get(url).send().unwrap();
    if response.status().is_success() {
        let memory_buffer: Vec<u8> = response.bytes().unwrap().to_vec();
        println!("下載完成，檔案大小: {} bytes", memory_buffer.len());

        println!("正在驗證檔案完整性...");

        let mut hasher = sha2::Sha256::new();
        hasher.update(&memory_buffer);

        let hash_hex = hex::encode(hasher.finalize());

        if hash_hex.eq_ignore_ascii_case(FRP_SHA256) {
            println!("檔案完整性驗證成功，SHA256: {}", hash_hex);
        } else {
            eprintln!(
                "檔案完整性驗證失敗，SHA256: {} (預期: {})",
                hash_hex, FRP_SHA256
            );
            return;
        }

        println!("正在解壓縮 frp...");
        let cursor = Cursor::new(memory_buffer);
        let mut archive = ZipArchive::new(cursor).expect("無法讀取 ZIP 檔案");
        let mut frpc_buffer = Vec::new();

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).expect("無法讀取 ZIP 檔案中的檔案");
            let file_name = file.name().expect("無法取得檔案名稱");

            if file_name.ends_with("frpc.exe") {
                println!("找到 frpc.exe，正在解壓縮...");
                file.read_to_end(&mut frpc_buffer)
                    .expect("無法解壓縮 frpc.exe");
                break;
            }
        }

        if frpc_buffer.is_empty() {
            eprintln!("在 ZIP 檔案中找不到 frpc.exe");
            return;
        }

        println!("frpc.exe 解壓縮完成，檔案大小: {} bytes", frpc_buffer.len());
    } else {
        eprintln!("下載失敗，HTTP 狀態碼: {}", response.status());
    }
}
