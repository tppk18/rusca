use std::net::SocketAddr;

use crate::model::{FindingKind};

mod ssh;
mod rtsp;
mod rtsp_authgrinder;
mod ftp;

pub use ssh::SSHBruteforceModule;
pub use rtsp::RTSPBruteforceModule;
pub use ftp::FTPBruteforceModule;

#[derive(Debug, Clone)]
pub struct BruteforceConfig {
    pub enabled: bool,
    pub username_file: String,
    pub password_file: String,
    pub max_attempts: usize,
    pub delay_ms: u64,
}

impl Default for BruteforceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            username_file: "usernames.txt".to_string(),
            password_file: "passwords.txt".to_string(),
            max_attempts: 1000,
            delay_ms: 500,
        }
    }
}

pub trait BruteforceModule: Send + Sync {
    fn name(&self) -> &'static str;
    fn supports(&self, service_kind: FindingKind) -> bool;
    fn start_bruteforce(&self, addr: SocketAddr, banner: String);
}

/// Загружает список слов из файла
pub async fn load_wordlist(filename: &str) -> Result<Vec<String>, String> {
    use tokio::{fs::File, io::{AsyncBufReadExt, BufReader}};
    use std::path::Path;
    
    let path = Path::new(filename);
    if !path.exists() {
        return Err(format!("File not found: {}", filename));
    }

    let file = File::open(path)
        .await
        .map_err(|e| format!("Failed to open {}: {}", filename, e))?;

    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    let mut wordlist = Vec::new();

    while let Some(line) = lines.next_line().await.map_err(|e| format!("Failed to read line from {}: {}", filename, e))? {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        wordlist.push(line.to_string());
    }

    if wordlist.is_empty() {
        return Err(format!("No valid entries in file: {}", filename));
    }

    Ok(wordlist)
}