use crate::modules::detect_service_and_build_finding;
use crate::model::{ScanParams, ServerMessage, Finding, FindingKind};
use crate::export::append_html_event;

use crate::bruteforce::{BruteforceConfig, BruteforceModule};
use crate::bruteforce_manager::BruteforceManager;

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::sync::mpsc::UnboundedSender;
use tracing::{error};

use async_std::task;
use rand::{seq::SliceRandom, Rng};

use myrustscan::address::parse_addresses;
use myrustscan::input::{Opts, ScanOrder};
use myrustscan::port_strategy::PortStrategy;
use myrustscan::scanner::Scanner;

/// Запуск сканирования в отдельном блокирующем таске
pub async fn run_scan_job(
    params: ScanParams,
    tx: UnboundedSender<String>,
    pause: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) {
    // Превью портов для статуса
    let ports_preview = if params.ports.is_empty() {
        "<нет портов>".to_string()
    } else if params.ports.len() <= 8 {
        params
            .ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    } else {
        let head: Vec<String> = params
            .ports
            .iter()
            .take(8)
            .map(|p| p.to_string())
            .collect();
        format!("{} … (+ ещё {} портов)", head.join(","), params.ports.len() - 8)
    };

    let start_msg = ServerMessage::Status {
        text: format!(
            "Запуск сканирования: порты [{}], timeout={}мс, ip_chunk_size={}",
            ports_preview, params.timeout_ms, params.ip_chunk_size
        ),
    };
    let _ = tx.send(serde_json::to_string(&start_msg).unwrap());

    let tx_clone = tx.clone();
    let paused_clone = pause.clone();
    let stop_clone = stop.clone();

    let res =
        tokio::task::spawn_blocking(move || run_scan_blocking(params, tx_clone, paused_clone, stop_clone))
            .await;

    match res {
        Ok(Ok(())) => {
            let _ = tx.send(serde_json::to_string(&ServerMessage::Finished).unwrap());
        }
        Ok(Err(err)) => {
            let _ = tx.send(
                serde_json::to_string(&ServerMessage::Error { error: err }).unwrap(),
            );
            let _ = tx
                .send(serde_json::to_string(&ServerMessage::Finished).unwrap());
        }
        Err(join_err) => {
            let _ = tx.send(
                serde_json::to_string(&ServerMessage::Error {
                    error: format!("Паника в сканере: {join_err}"),
                })
                .unwrap(),
            );
            let _ = tx
                .send(serde_json::to_string(&ServerMessage::Finished).unwrap());
        }
    }
}

fn post_process_socket(
    addr: &SocketAddr, 
    tx: &UnboundedSender<String>, 
    bruteforce_config: &BruteforceConfig,
    finding_opt: &Option<Finding>,
) {
    if let Some(finding) = finding_opt {
        // Создаем менеджер брутфорса
        let bruteforce_manager = BruteforceManager::new(tx.clone(), bruteforce_config.clone());
        
        // Запускаем брутфорс для соответствующих сервисов
        match finding.kind {
            FindingKind::SshService => {
                // Получаем баннер из finding.details или используем заглушку
                let banner = finding.details.clone().unwrap_or_else(|| "SSH service".to_string());
                bruteforce_manager.start_bruteforce(*addr, banner, FindingKind::SshService);
            }

            FindingKind::RtspService => {
                // Получаем баннер из finding.details или используем заглушку
                let banner = finding.details.clone().unwrap_or_else(|| "RTSP service".to_string());
                bruteforce_manager.start_bruteforce(*addr, banner, FindingKind::RtspService);
            }

            FindingKind::FtpService => {
                // Получаем баннер из finding.details или используем заглушку
                let banner = finding.details.clone().unwrap_or_else(|| "FTP service".to_string());
                bruteforce_manager.start_bruteforce(*addr, banner, FindingKind::FtpService);
            }
            // Добавим другие сервисы позже
            _ => {}
        }
    }
}

/// Блокирующая часть: сканирует порты чанками, поддерживает паузу
pub fn run_scan_blocking(
    params: ScanParams,
    tx: UnboundedSender<String>,
    pause: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    // 1. Порты только списком
    if params.ports.is_empty() {
        return Err("Не указаны порты для сканирования".to_owned());
    }

    let mut ports: Vec<u16> = params
        .ports
        .iter()
        .copied()
        .filter(|p| *p > 0)
        .collect();
    ports.sort_unstable();
    ports.dedup();

    if ports.is_empty() {
        return Err("После фильтрации список портов пуст".to_owned());
    }

    // 2. Собираем адреса из UI + файла
    let addresses = build_address_list(&params.addresses_text, &params.file_text)?;

    let msg = ServerMessage::Status {
        text: format!("После парсинга адресов: {} элементов", addresses.len()),
    };
    let _ = tx.send(serde_json::to_string(&msg).unwrap());

    // 3. Опции myrustscan
    let mut opts = Opts::default();
    opts.addresses = addresses;
    opts.greppable = true;
    opts.accessible = params.accessible;
    opts.udp = params.udp;

    let mut ips: Vec<IpAddr> = parse_addresses(&opts);

    // 4. Добавляем случайные IP, если нужно
    if params.random_targets > 0 {
        let mut rng = rand::thread_rng();
        let mut set: HashSet<IpAddr> = ips.iter().cloned().collect();

        let mut added = 0u32;
        while added < params.random_targets {
            let raw: u32 = rng.gen();
            let ip = IpAddr::V4(Ipv4Addr::from(raw));
            if set.insert(ip) {
                ips.push(ip);
                added += 1;
            }
        }

        let msg = ServerMessage::Status {
            text: format!("Добавлено {} случайных IP", added),
        };
        let _ = tx.send(serde_json::to_string(&msg).unwrap());
    }

    if ips.is_empty() {
        return Err("Не удалось разрешить ни один адрес".to_owned());
    }

    // 5. Shuffle адресов (обязательно, независимо от random_order)
    {
        let mut rng = rand::thread_rng();
        ips.shuffle(&mut rng);
    }

    let msg = ServerMessage::Status {
        text: format!("Всего IP к сканированию (после shuffle): {}", ips.len()),
    };
    let _ = tx.send(serde_json::to_string(&msg).unwrap());

    // 6. Исключаемые порты
    let exclude_ports: Vec<u16> = params
        .exclude_ports
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter_map(|s| s.parse::<u16>().ok())
        .collect();

    // 7. Прогресс: IP * порты
    let total_units: u64 = ips.len() as u64 * ports.len() as u64;
    let mut completed_units: u64 = 0;

    // 8. Защита от Too many open files
    const MAX_SAFE_BATCH: u16 = 2500;
    let effective_batch = params.batch_size.min(MAX_SAFE_BATCH);
    if effective_batch != params.batch_size {
        let warn = ServerMessage::Status {
            text: format!(
                "Batch size {} слишком большой, снижаю до {} (чтобы не ловить 'Too many open files')",
                params.batch_size, effective_batch
            ),
        };
        let _ = tx.send(serde_json::to_string(&warn).unwrap());
    }

    // 9. Чанкование по IP
    let ip_chunk_size = if params.ip_chunk_size == 0 {
        256
    } else {
        params.ip_chunk_size.min(10_000)
    };

    let scan_order = if params.random_order {
        ScanOrder::Random
    } else {
        ScanOrder::Serial
    };
    let timeout = Duration::from_millis(params.timeout_ms as u64);

    let mut ip_offset: usize = 0;
    while ip_offset < ips.len() {
        // Пауза
        if stop.load(Ordering::SeqCst) {
            let _ = tx.send(serde_json::to_string(&ServerMessage::Status {
                text: "Сканирование остановлено пользователем".to_string(),
            }).unwrap());
            let _ = tx.send(serde_json::to_string(&ServerMessage::Finished).unwrap());
            return Ok(());
        }

        // пауза
        while pause.load(Ordering::SeqCst) {
            if stop.load(Ordering::SeqCst) {
                let _ = tx.send(serde_json::to_string(&ServerMessage::Status {
                    text: "Сканирование остановлено во время паузы".to_string(),
                }).unwrap());
                let _ = tx.send(serde_json::to_string(&ServerMessage::Finished).unwrap());
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        let ip_end = std::cmp::min(ips.len(), ip_offset + ip_chunk_size);
        let ip_chunk = &ips[ip_offset..ip_end];
        let ip_chunk_len = (ip_end - ip_offset) as u64;

        let port_strategy = PortStrategy::pick(&None, Some(ports.clone()), scan_order);

        let scanner = Scanner::new(
            ip_chunk,
            effective_batch,
            timeout,
            params.tries,
            true, // greppable
            port_strategy,
            params.accessible,
            exclude_ports.clone(),
            params.udp,
        );

        let bruteforce_config = BruteforceConfig {
            enabled: params.bruteforce_enabled,
            username_file: params.username_file.clone(),
            password_file: params.password_file.clone(),
            max_attempts: params.max_attempts,
            delay_ms: params.bruteforce_delay_ms,
        };

        let open_sockets: Vec<SocketAddr> = task::block_on(scanner.run());

        for addr in open_sockets {
            // 1) ВСЕГДА сначала сообщаем об открытом порте
            let msg = ServerMessage::Port {
                addr: addr.to_string(),
            };
            let _ = tx.send(serde_json::to_string(&msg).unwrap());

            // 2) Пытаемся определить сервис
            let finding_opt = detect_service_and_build_finding(&addr);

            if let Some(finding) = finding_opt.clone() {
                // отправляем в WebSocket
                let msg = ServerMessage::Finding { finding };
                let _ = tx.send(serde_json::to_string(&msg).unwrap());
            }

            post_process_socket(&addr, &tx, &bruteforce_config, &finding_opt);

            // 3) Пишем в HTML-лог (даже если finding == None — просто без типа/деталей)
            if let Err(e) = append_html_event(&addr, finding_opt.as_ref()) {
                error!("Не удалось дописать HTML-лог: {e}");
                let msg = ServerMessage::Error {
                    error: format!("Не удалось дописать HTML-лог: {e}"),
                };
                let _ = tx.send(serde_json::to_string(&msg).unwrap());
            }
        }



        // 3) Обновляем прогресс
        completed_units = completed_units.saturating_add(ip_chunk_len * ports.len() as u64);

        let prog = ServerMessage::Progress {
            completed: completed_units,
            total: total_units,
        };
        let _ = tx.send(serde_json::to_string(&prog).unwrap());

        ip_offset = ip_end;
    }

    Ok(())
}

/* -------------------- Address parsing with ranges ------------------------- */

fn build_address_list(ui_text: &str, file_text: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::<String>::new();

    let mut combined = String::new();
    combined.push_str(ui_text);
    if !file_text.is_empty() {
        combined.push('\n');
        combined.push_str(file_text);
    }

    for line in combined.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        for token in line
            .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            // Диапазон IP-IP без CIDR
            if token.contains('-') && !token.contains('/') {
                match expand_ipv4_range(token) {
                    Ok(mut v) => {
                        out.append(&mut v);
                        continue;
                    }
                    Err(e) => {
                        error!("Ошибка парсинга диапазона '{token}': {e}");
                    }
                }
            }

            // Остальное отдаём parse_addresses (IP, CIDR, домены, файлы)
            out.push(token.to_string());
        }
    }

    // if out.is_empty() {
    //     return Err("Не удалось распознать ни одного адреса".to_owned());
    // }

    Ok(out)
}

fn expand_ipv4_range(token: &str) -> Result<Vec<String>, String> {
    let (start_s, end_s) = token
        .split_once('-')
        .ok_or_else(|| format!("Неверный диапазон: {token}"))?;

    let start: Ipv4Addr = start_s
        .trim()
        .parse()
        .map_err(|e| format!("Неверный IP в диапазоне '{start_s}': {e}"))?;
    let end: Ipv4Addr = end_s
        .trim()
        .parse()
        .map_err(|e| format!("Неверный IP в диапазоне '{end_s}': {e}"))?;

    let start_u = u32::from(start);
    let end_u = u32::from(end);

    if start_u > end_u {
        return Err(format!(
            "Начальный IP больше конечного в диапазоне '{token}'"
        ));
    }

    let count = (end_u - start_u) as u64 + 1;
    const MAX_EXPANDED: u64 = 1_000_000;
    if count > MAX_EXPANDED {
        return Err(format!(
            "Диапазон слишком большой ({count} адресов), лимит {MAX_EXPANDED}"
        ));
    }

    let mut res = Vec::with_capacity(count as usize);
    for v in start_u..=end_u {
        res.push(Ipv4Addr::from(v).to_string());
    }
    Ok(res)
}
