use std::{net::SocketAddr};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Semaphore;
use once_cell::sync::Lazy;

use crate::model::{FindingKind, ServerMessage, Finding};
use crate::export::update_html_event;
use super::{BruteforceModule, BruteforceConfig, load_wordlist};

use crate::bruteforce::rtsp_authgrinder::{brute_force_target, capture_snapshot_rtsp, AuthResult};
use tracing::{error};

static RTSP_BRUTE_SEMAPHORE: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(3));

pub struct RTSPBruteforceModule {
    tx: UnboundedSender<String>,
    config: BruteforceConfig,
}

impl RTSPBruteforceModule {
    pub fn new(tx: UnboundedSender<String>, config: BruteforceConfig) -> Self {
        Self { tx, config }
    }
}

impl BruteforceModule for RTSPBruteforceModule {
    fn name(&self) -> &'static str {
        "rtsp"
    }

    fn supports(&self, service_kind: FindingKind) -> bool {
        matches!(service_kind, FindingKind::RtspService)
    }

    fn start_bruteforce(&self, addr: SocketAddr, banner: String) {
        if !self.config.enabled {
            return;
        }

        let tx = self.tx.clone();
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let _permit = RTSP_BRUTE_SEMAPHORE
                .acquire()
                .await
                .expect("semaphore closed");

            let (usernames, passwords) = match load_wordlists(&config).await {
                Some((u, p)) => (u, p),
                None => return,
            };

            // --------- ВСТРОЙКА БИБЛИОТЕКИ ТУТ ---------

            let target_ip = addr.ip().to_string();
            let target_port = addr.port();

            // Возьми поле, в котором у тебя хранится число потоков.
            // Ниже я предполагаю, что оно называется config.threads,
            // но подставь своё.
            let threads = 20;

            // Запускаем синхронный брутфорс в отдельном blocking-треде,
            // чтобы не блокировать tokio-лооп
            let results: Vec<AuthResult> = match tokio::task::spawn_blocking(move || {
                brute_force_target(
                    target_ip,
                    target_port,
                    usernames,
                    passwords,
                    threads,
                )
            }).await {
                Ok(r) => r,
                Err(e) => {
                    // можно залогировать ошибку, если надо
                    eprintln!("rtsp bruteforce task panicked: {e}");
                    return;
                }
            };

            // Обработка результатов: отправляем их дальше через tx
            for res in results {
                // тут зависит от того, какой у тебя формат ServerMessage/Finding.
                // Примерно так:

                let finding = Finding {
                    addr: addr.to_string(),
                    kind: FindingKind::RtspService,
                    title: Some("RTSP Camera Access".to_string()),
                    details: Some(format!("Credentials found: {}:{}", res.username.clone(), res.password.clone())),
                };

                if let Err(e) = update_html_event(&addr, Some(&finding)) {
                    error!("Не удалось дописать HTML-лог: {e}");
                    let msg = ServerMessage::Error {
                        error: format!("Не удалось дописать HTML-лог: {e}"),
                    };
                    let _ = tx.send(serde_json::to_string(&msg).unwrap());
                }

                let screen_cast: std::io::Result<()> = match tokio::task::spawn_blocking(move || {
                    capture_snapshot_rtsp(addr.ip().to_string(),
                    target_port,
                    &res.username.clone(),
                    &res.password.clone())
                }).await {
                    Ok(r) => r,
                    Err(e) => {
                        // можно залогировать ошибку, если надо
                        eprintln!("rtsp screencast task panicked: {e}");
                        return;
                    }
                };

                if let Ok(msg) = serde_json::to_string(&ServerMessage::Finding { finding }) {
                    let _ = tx.send(msg);
                }
            }
        });
    }
}

async fn load_wordlists(config: &BruteforceConfig) -> Option<(Vec<String>, Vec<String>)> {
    let usernames = vec![
                            "admin".to_string(),
                            "default".to_string()
                        ];
    let passwords = load_wordlist(&config.password_file).await.ok()?;
    
    if usernames.is_empty() || passwords.is_empty() {
        None
    } else {
        Some((usernames, passwords))
    }
}

