use ssh2::{Session, Error};
use std::{net::SocketAddr, time::Duration};
use tokio::{sync::mpsc::UnboundedSender, task};
use tracing::{info, warn};

use crate::model::{FindingKind, ServerMessage, Finding};
use super::{BruteforceModule, BruteforceConfig, load_wordlist};

pub struct SSHBruteforceModule {
    tx: UnboundedSender<String>,
    config: BruteforceConfig,
}

impl SSHBruteforceModule {
    pub fn new(tx: UnboundedSender<String>, config: BruteforceConfig) -> Self {
        Self { tx, config }
    }
}

impl BruteforceModule for SSHBruteforceModule {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn supports(&self, service_kind: FindingKind) -> bool {
        matches!(service_kind, FindingKind::SshService)
    }

    fn start_bruteforce(&self, addr: SocketAddr, banner: String) {
        if !self.config.enabled {
            return;
        }

        let tx = self.tx.clone();
        let config = self.config.clone();
        
        tokio::spawn(async move {
            info!("Starting SSH bruteforce for {} with files: {} / {}", 
                  addr, config.username_file, config.password_file);
            
            // Загружаем логины и пароли из файлов
            let usernames = match load_wordlist(&config.username_file).await {
                Ok(list) if !list.is_empty() => list,
                Ok(_) => {
                    let msg = ServerMessage::Error {
                        error: format!("Username file is empty: {}", config.username_file),
                    };
                    let _ = tx.send(serde_json::to_string(&msg).unwrap());
                    return;
                }
                Err(e) => {
                    let msg = ServerMessage::Error {
                        error: format!("Failed to load username file: {}", e),
                    };
                    let _ = tx.send(serde_json::to_string(&msg).unwrap());
                    return;
                }
            };

            let passwords = match load_wordlist(&config.password_file).await {
                Ok(list) if !list.is_empty() => list,
                Ok(_) => {
                    let msg = ServerMessage::Error {
                        error: format!("Password file is empty: {}", config.password_file),
                    };
                    let _ = tx.send(serde_json::to_string(&msg).unwrap());
                    return;
                }
                Err(e) => {
                    let msg = ServerMessage::Error {
                        error: format!("Failed to load password file: {}", e),
                    };
                    let _ = tx.send(serde_json::to_string(&msg).unwrap());
                    return;
                }
            };

            let total_attempts = usernames.len() * passwords.len();
            let max_attempts = config.max_attempts.min(total_attempts);
            let mut attempts = 0;

            info!("Loaded {} usernames and {} passwords for SSH bruteforce", 
                  usernames.len(), passwords.len());

            let status_msg = ServerMessage::Status {
                text: format!("SSH bruteforce starting for {}: {} usernames × {} passwords = {} total attempts (limited to {})", 
                    addr, usernames.len(), passwords.len(), total_attempts, max_attempts),
            };
            let _ = tx.send(serde_json::to_string(&status_msg).unwrap());

            'outer: for username in &usernames {
                for password in &passwords {
                    if attempts >= max_attempts {
                        let msg = ServerMessage::Status {
                            text: format!("SSH bruteforce for {} stopped: reached max attempts ({})", addr, max_attempts),
                        };
                        let _ = tx.send(serde_json::to_string(&msg).unwrap());
                        break 'outer;
                    }

                    attempts += 1;

                    // Отправляем прогресс каждые 10 попыток
                    if attempts % 10 == 0 {
                        let progress_msg = ServerMessage::Status {
                            text: format!("SSH bruteforce progress for {}: {}/{} attempts ({}%)", 
                                addr, attempts, max_attempts, (attempts * 100) / max_attempts),
                        };
                        let _ = tx.send(serde_json::to_string(&progress_msg).unwrap());
                    }

                    // Клонируем строки для передачи в spawn_blocking
                    let username_clone = username.clone();
                    let password_clone = password.clone();
                    
                    match try_ssh_connect(addr, username_clone, password_clone).await {
                        Ok(true) => {
                            let finding = Finding {
                                addr: addr.to_string(),
                                kind: FindingKind::SshService,
                                title: Some("SSH Bruteforce Success".to_string()),
                                details: Some(format!("Credentials found: {}:{}", username, password)),
                            };

                            // Отправляем Finding
                            let msg = ServerMessage::Finding { finding };
                            let _ = tx.send(serde_json::to_string(&msg).unwrap());

                            let success_msg = ServerMessage::Status {
                                text: format!("SSH bruteforce SUCCESS: {} - {}:{} (attempt {})", 
                                    addr, username, password, attempts),
                            };
                            let _ = tx.send(serde_json::to_string(&success_msg).unwrap());
                            
                            info!("SSH bruteforce success for {}: {}:{} (attempt {})", 
                                  addr, username, password, attempts);
                            return;
                        }
                        Ok(false) => {
                            // Неверные credentials, продолжаем
                        }
                        Err(e) => {
                            warn!("SSH connection error for {}: {}", addr, e);
                            let error_msg = ServerMessage::Status {
                                text: format!("SSH bruteforce connection error for {}: {} (stopping)", addr, e),
                            };
                            let _ = tx.send(serde_json::to_string(&error_msg).unwrap());
                            return;
                        }
                    }

                    // Задержка между попытками
                    tokio::time::sleep(Duration::from_millis(config.delay_ms)).await;
                }
            }

            let finish_msg = ServerMessage::Status {
                text: format!("SSH bruteforce finished for {}: {} attempts, no credentials found", addr, attempts),
            };
            let _ = tx.send(serde_json::to_string(&finish_msg).unwrap());
        });
    }
}

// Изменяем сигнатуру на владеющие String вместо &str
async fn try_ssh_connect(addr: SocketAddr, username: String, password: String) -> Result<bool, String> {
    task::spawn_blocking(move || {
        let tcp = match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(tcp) => tcp,
            Err(e) => return Err(format!("TCP connection failed: {}", e)),
        };

        // Session::new() возвращает Result, а не Option
        let mut session = match Session::new() {
            Ok(session) => session,
            Err(e) => return Err(format!("Failed to create SSH session: {}", e)),
        };

        session.set_tcp_stream(tcp);
        
        if let Err(e) = session.handshake() {
            return Err(format!("SSH handshake failed: {}", e));
        }

        // Используем владеющие String
        match session.userauth_password(&username, &password) {
            Ok(()) if session.authenticated() => Ok(true),
            Ok(()) => Ok(false), // Аутентификация не прошла
            Err(e) if e.to_string().contains("Authentication failed") => Ok(false),
            Err(e) => Err(format!("Authentication error: {}", e)),
        }
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}