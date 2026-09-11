use log::{debug, error, info};
use reqwest::blocking::Client;
use sha2::Digest;
use std::io::{Cursor, Read};
use zip::ZipArchive;

pub fn fetch_frpc() -> Option<Vec<u8>> {
    let url =
        "https://github.com/fatedier/frp/releases/download/v0.63.0/frp_0.63.0_windows_amd64.zip";
    const FRP_SHA256: &str = "d76af76641ecc64719820f9f81a3eec6b76ad9f8ab43458eb8cd98554201f771";
    let client = Client::builder()
        .user_agent("TaiwanFRP-Agent/1.0")
        .build()
        .unwrap();

    info!("Downloading frp...");
    let response = client.get(url).send().unwrap();
    if !response.status().is_success() {
        error!("Download failed, HTTP status code: {}", response.status());
        return None;
    }

    let memory_buffer: Vec<u8> = response.bytes().unwrap().to_vec();
    debug!(
        "Download complete, file size: {} bytes",
        memory_buffer.len()
    );

    // SHA256 驗證
    info!("Verifying file integrity...");
    let mut hasher = sha2::Sha256::new();
    hasher.update(&memory_buffer);
    let hash_hex = hex::encode(hasher.finalize());

    if !hash_hex.eq_ignore_ascii_case(FRP_SHA256) {
        error!(
            "File integrity verification failed, SHA256: {} (expected: {})",
            hash_hex, FRP_SHA256
        );
        return None;
    }
    debug!(
        "File integrity verification successful, SHA256: {}",
        hash_hex
    );
    info!("File integrity verification successful");

    // 解壓 frpc.exe
    info!("Extracting frp...");
    let cursor = Cursor::new(memory_buffer);
    let mut archive = ZipArchive::new(cursor).expect("Failed to read ZIP file");
    let mut frpc_buffer = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .expect("Failed to read file from ZIP file");
        let file_name = file.name().expect("Failed to get file name");

        if file_name.ends_with("frpc.exe") {
            info!("Found frpc.exe, extracting...");
            file.read_to_end(&mut frpc_buffer)
                .expect("Failed to extract frpc.exe");
            break;
        }
    }

    if frpc_buffer.is_empty() {
        error!("frpc.exe not found in the ZIP archive!");
        return None;
    }
    debug!(
        "frpc.exe extraction complete, file size: {} bytes",
        frpc_buffer.len()
    );

    Some(frpc_buffer)
}
