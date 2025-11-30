use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::model::{Finding, FindingKind};

/// Сколько байт максимум читаем из сокета
const MAX_BANNER_LEN: usize = 4096;

/// Обёртка над ответом сервиса
#[derive(Debug, Clone)]
pub struct ServiceProbe {
    pub addr: SocketAddr,
    pub raw: Vec<u8>,
    pub text: String,
}

/// Базовый интерфейс модуля обнаружения сервиса
pub trait ServiceModule: Send + Sync {
    /// Имя модуля (для отладки)
    fn name(&self) -> &'static str;

    /// Проверяет, подходит ли модуль к этому ответу
    fn matches(&self, addr: &SocketAddr, text: &str, raw: &[u8]) -> bool;

    /// Собирает Finding для этого ответа
    fn make_finding(&self, addr: &SocketAddr, text: &str, raw: &[u8]) -> Finding;
}

/* ====================== ПРОБИНГ СЕРВИСА ====================== */

/// Пробуем подключиться и вытащить баннер / headers.
/// В зависимости от порта иногда шлём небольшой запрос (HTTP, Redis, RTSP и т.п.)
fn probe_service(addr: &SocketAddr) -> Option<ServiceProbe> {
    let connect_timeout = Duration::from_millis(1500);
    let read_timeout = Duration::from_millis(1000);

    let mut stream = TcpStream::connect_timeout(addr, connect_timeout).ok()?;
    stream.set_read_timeout(Some(read_timeout)).ok();
    stream.set_write_timeout(Some(read_timeout)).ok();

    let port = addr.port();

    // Буфер под ответ
    let mut buf = [0u8; MAX_BANNER_LEN];
    let mut data = Vec::new();

    // Для некоторых портов сразу шлём лёгкий запрос, чтобы сервис ответил
    match port {
        80 | 8080 | 8000 | 443 | 8443 | 9200 => {
            // HTTP / Elasticsearch
            let req = format!(
                "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: rusca-prober\r\n\r\n",
                addr.ip()
            );
            let _ = stream.write_all(req.as_bytes());
        }
        2375 | 2376 => {
            // Docker API ping
            let req = format!(
                "GET /_ping HTTP/1.0\r\nHost: {}\r\nUser-Agent: rusca-prober\r\n\r\n",
                addr.ip()
            );
            let _ = stream.write_all(req.as_bytes());
        }
        6379 => {
            // Redis PING
            let _ = stream.write_all(b"PING\r\n");
        }
        554 => {
            // RTSP OPTIONS
            let req = format!(
                "OPTIONS rtsp://{}:{}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: rusca-prober\r\n\r\n",
                addr.ip(),
                addr.port()
            );
            let _ = stream.write_all(req.as_bytes());
        }
        _ => {
            // SSH/FTP/Telnet/VNC/RDP обычно сами шлют баннер при коннекте,
            // ничего не отправляем.
        }
    }

    // Пытаемся прочитать ответ
    if let Ok(n) = stream.read(&mut buf) {
        if n > 0 {
            data.extend_from_slice(&buf[..n]);
        }
    }

    if data.is_empty() {
        return None;
    }

    let text = String::from_utf8_lossy(&data).to_string();

    Some(ServiceProbe {
        addr: *addr,
        raw: data,
        text,
    })
}

/* ====================== НАБОР МОДУЛЕЙ ====================== */

/// Приоритетный список модулей.
/// Порядок важен: кто первый `matches` — тот и обслуживает.
fn modules() -> Vec<Box<dyn ServiceModule>> {
    vec![
        Box::new(SshModule),
        Box::new(FtpModule),
        Box::new(RtspModule),
        Box::new(VncModule),
        Box::new(RdpModule),
        Box::new(RedisModule),
        Box::new(MongoModule),
        Box::new(DockerModule),
        Box::new(ElasticModule),
        Box::new(TelnetModule),
        Box::new(SnmpModule),
        Box::new(ModbusModule),
        Box::new(HttpModule),
        Box::new(GenericModule),
    ]
}

/* ====================== УТИЛИТЫ ПАРСИНГА ====================== */

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().trim().to_string()
}

fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/* ====================== КОНКРЕТНЫЕ МОДУЛИ ====================== */

/* ---- HTTP ---- */

struct HttpModule;

impl ServiceModule for HttpModule {
    fn name(&self) -> &'static str {
        "http"
    }

    fn matches(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> bool {
        let port = addr.port();
        text.contains("HTTP/1.") || text.contains("HTTP/2.")
            || matches!(port, 80 | 8080 | 8000 | 443 | 8443)
    }

    fn make_finding(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> Finding {
        // status line
        let status = first_line(text);

        // title
        let mut title = None;
        let lower = text.to_lowercase();
        if let Some(start) = lower.find("<title") {
            if let Some(gt) = lower[start..].find('>') {
                let rest = &text[start + gt + 1..];
                if let Some(end) = rest.to_lowercase().find("</title>") {
                    title = Some(rest[..end].trim().to_string());
                }
            }
        }

        Finding {
            addr: addr.to_string(),
            kind: FindingKind::HttpService,
            title,
            details: if status.is_empty() { None } else { Some(status) },
        }
    }
}

/* ---- SSH ---- */

struct SshModule;

impl ServiceModule for SshModule {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn matches(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> bool {
        text.starts_with("SSH-") || addr.port() == 22
    }

    fn make_finding(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> Finding {
        let banner = first_line(text);
        Finding {
            addr: addr.to_string(),
            kind: FindingKind::SshService,
            title: None,
            details: if banner.is_empty() { None } else { Some(banner) },
        }
    }
}

/* ---- FTP ---- */

struct FtpModule;

impl ServiceModule for FtpModule {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn matches(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> bool {
        let line = first_line(text);
        (line.starts_with("220") && contains_case_insensitive(&line, "ftp"))
            || addr.port() == 21
    }

    fn make_finding(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> Finding {
        let banner = first_line(text);
        Finding {
            addr: addr.to_string(),
            kind: FindingKind::FtpService,
            title: None,
            details: if banner.is_empty() { None } else { Some(banner) },
        }
    }
}

/* ---- RTSP ---- */

struct RtspModule;

impl ServiceModule for RtspModule {
    fn name(&self) -> &'static str {
        "rtsp"
    }

    fn matches(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> bool {
        contains_case_insensitive(text, "RTSP/1.0") || addr.port() == 554
    }

    fn make_finding(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> Finding {
        let status = first_line(text);
        Finding {
            addr: addr.to_string(),
            kind: FindingKind::RtspService, // можно добавить отдельный RtspService
            title: Some("RTSP".to_string()),
            details: if status.is_empty() { None } else { Some(status) },
        }
    }
}

/* ---- VNC ---- */

struct VncModule;

impl ServiceModule for VncModule {
    fn name(&self) -> &'static str {
        "vnc"
    }

    fn matches(&self, addr: &SocketAddr, _text: &str, raw: &[u8]) -> bool {
        let port = addr.port();
        (raw.starts_with(b"RFB ") && raw.len() >= 12) || (5900..=5903).contains(&port)
    }

    fn make_finding(&self, addr: &SocketAddr, _text: &str, raw: &[u8]) -> Finding {
        let ver = if raw.len() >= 12 {
            String::from_utf8_lossy(&raw[..12]).trim().to_string()
        } else {
            "VNC server".to_string()
        };

        Finding {
            addr: addr.to_string(),
            kind: FindingKind::VncService,
            title: Some("VNC".to_string()),
            details: Some(ver),
        }
    }
}

/* ---- RDP ---- */

struct RdpModule;

impl ServiceModule for RdpModule {
    fn name(&self) -> &'static str {
        "rdp"
    }

    fn matches(&self, addr: &SocketAddr, _text: &str, raw: &[u8]) -> bool {
        let port = addr.port();
        if port != 3389 {
            return false;
        }
        // Очень грубый хак: RDP идёт поверх TPKT, первые байты 0x03 0x00 ...
        raw.len() >= 4 && raw[0] == 0x03 && raw[1] == 0x00
    }

    fn make_finding(&self, addr: &SocketAddr, _text: &str, _raw: &[u8]) -> Finding {
        Finding {
            addr: addr.to_string(),
            kind: FindingKind::RdpService,
            title: Some("RDP".to_string()),
            details: None,
        }
    }
}

/* ---- Redis ---- */

struct RedisModule;

impl ServiceModule for RedisModule {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn matches(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> bool {
        let port = addr.port();
        text.starts_with("+PONG")
            || text.starts_with("-ERR")
            || port == 6379
    }

    fn make_finding(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> Finding {
        let line = first_line(text);
        Finding {
            addr: addr.to_string(),
            kind: FindingKind::RedisService,
            title: Some("Redis".to_string()),
            details: if line.is_empty() { None } else { Some(line) },
        }
    }
}

/* ---- MongoDB ---- */

struct MongoModule;

impl ServiceModule for MongoModule {
    fn name(&self) -> &'static str {
        "mongo"
    }

    fn matches(&self, addr: &SocketAddr, _text: &str, _raw: &[u8]) -> bool {
        addr.port() == 27017
    }

    fn make_finding(&self, addr: &SocketAddr, _text: &str, _raw: &[u8]) -> Finding {
        Finding {
            addr: addr.to_string(),
            kind: FindingKind::MongoService,
            title: Some("MongoDB".to_string()),
            details: None,
        }
    }
}

/* ---- Docker API ---- */

struct DockerModule;

impl ServiceModule for DockerModule {
    fn name(&self) -> &'static str {
        "docker_api"
    }

    fn matches(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> bool {
        let port = addr.port();
        contains_case_insensitive(text, "docker") || matches!(port, 2375 | 2376)
    }

    fn make_finding(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> Finding {
        let line = first_line(text);
        Finding {
            addr: addr.to_string(),
            kind: FindingKind::DockerService,
            title: Some("Docker API".to_string()),
            details: if line.is_empty() { None } else { Some(line) },
        }
    }
}

/* ---- Elasticsearch ---- */

struct ElasticModule;

impl ServiceModule for ElasticModule {
    fn name(&self) -> &'static str {
        "elasticsearch"
    }

    fn matches(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> bool {
        let port = addr.port();
        contains_case_insensitive(text, "You Know, for Search")
            || text.contains("\"cluster_name\"")
            || port == 9200
    }

    fn make_finding(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> Finding {
        let line = first_line(text);
        Finding {
            addr: addr.to_string(),
            kind: FindingKind::ElasticService,
            title: Some("Elasticsearch".to_string()),
            details: if line.is_empty() { None } else { Some(line) },
        }
    }
}

/* ---- Telnet ---- */

struct TelnetModule;

impl ServiceModule for TelnetModule {
    fn name(&self) -> &'static str {
        "telnet"
    }

    fn matches(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> bool {
        let port = addr.port();
        port == 23
            || contains_case_insensitive(text, "telnet")
            || contains_case_insensitive(text, "login:")
    }

    fn make_finding(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> Finding {
        let line = first_line(text);
        Finding {
            addr: addr.to_string(),
            kind: FindingKind::TelnetService,
            title: Some("Telnet".to_string()),
            details: if line.is_empty() { None } else { Some(line) },
        }
    }
}

/* ---- SNMP (по порту, UDP в основном) ---- */

struct SnmpModule;

impl ServiceModule for SnmpModule {
    fn name(&self) -> &'static str {
        "snmp"
    }

    fn matches(&self, addr: &SocketAddr, _text: &str, _raw: &[u8]) -> bool {
        addr.port() == 161
    }

    fn make_finding(&self, addr: &SocketAddr, _text: &str, _raw: &[u8]) -> Finding {
        Finding {
            addr: addr.to_string(),
            kind: FindingKind::SnmpService,
            title: Some("SNMP (guess by port)".to_string()),
            details: None,
        }
    }
}

/* ---- Modbus ---- */

struct ModbusModule;

impl ServiceModule for ModbusModule {
    fn name(&self) -> &'static str {
        "modbus"
    }

    fn matches(&self, addr: &SocketAddr, _text: &str, _raw: &[u8]) -> bool {
        addr.port() == 502
    }

    fn make_finding(&self, addr: &SocketAddr, _text: &str, _raw: &[u8]) -> Finding {
        Finding {
            addr: addr.to_string(),
            kind: FindingKind::ModbusService,
            title: Some("Modbus (guess by port)".to_string()),
            details: None,
        }
    }
}

/* ---- Generic ---- */

struct GenericModule;

impl ServiceModule for GenericModule {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn matches(&self, _addr: &SocketAddr, _text: &str, _raw: &[u8]) -> bool {
        true
    }

    fn make_finding(&self, addr: &SocketAddr, text: &str, _raw: &[u8]) -> Finding {
        let line = first_line(text);
        Finding {
            addr: addr.to_string(),
            kind: FindingKind::GenericService,
            title: None,
            details: if line.is_empty() { None } else { Some(line) },
        }
    }
}

/* ====================== ВНЕШНИЙ API ДЛЯ SCAN.RS ====================== */

/// Главная точка входа: пробуем прозондировать сервис и построить Finding.
/// Гарантия: если порт открыт, всегда вернётся хотя бы generic-находка.
pub fn detect_service_and_build_finding(addr: &SocketAddr) -> Option<Finding> {
    // Пробуем вытащить баннер
    let probe = match probe_service(addr) {
        Some(p) => p,
        None => {
            // ничего не прочитали — но порт открыт, считаем generic
            return Some(Finding {
                addr: addr.to_string(),
                kind: FindingKind::GenericService,
                title: None,
                details: None,
            });
        }
    };

    let modules = modules();
    let text = probe.text.as_str();
    let raw = probe.raw.as_slice();

    // Все модули, кроме последнего (generic)
    for m in modules.iter().take(modules.len().saturating_sub(1)) {
        if m.matches(&probe.addr, text, raw) {
            return Some(m.make_finding(&probe.addr, text, raw));
        }
    }

    // Последний модуль — GenericModule
    if let Some(last) = modules.last() {
        return Some(last.make_finding(&probe.addr, text, raw));
    }

    None
}
