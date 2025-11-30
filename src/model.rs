use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use once_cell::sync::Lazy;

#[derive(Clone, Default)]
pub struct RuntimeState {
    pub running: bool,
    pub paused: bool,
    pub last_status: String,
    pub completed: u64,
    pub total: u64,
}

pub static RUNTIME_STATE: Lazy<RwLock<RuntimeState>> =
    Lazy::new(|| RwLock::new(RuntimeState::default()));

/// Параметры сканирования, приходят с фронта
#[derive(Debug, Deserialize, Clone)]
pub struct ScanParams {
    pub addresses_text: String,
    #[serde(default)]
    pub file_text: String,

    /// Перечень портов: 22,80,443…
    #[serde(default)]
    pub ports: Vec<u16>,

    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u32,
    #[serde(default = "default_batch_size")]
    pub batch_size: u16,
    #[serde(default = "default_ip_chunk_size")]
    pub ip_chunk_size: usize,
    #[serde(default = "default_tries")]
    pub tries: u8,

    /// Сколько случайных IP добавить (0 = не добавлять)
    #[serde(default)]
    pub random_targets: u32,

    /// Рандомный порядок **портов** (адреса мы всё равно тасуем)
    #[serde(default)]
    pub random_order: bool,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub accessible: bool,

    #[serde(default)]
    pub exclude_ports: String,

    #[serde(default)]
    pub bruteforce_enabled: bool,
    #[serde(default = "default_username_file")]
    pub username_file: String,
    #[serde(default = "default_password_file")]
    pub password_file: String,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: usize,
    #[serde(default = "default_bruteforce_delay")]
    pub bruteforce_delay_ms: u64,
}

fn default_timeout_ms() -> u32 {
    1000
}
fn default_batch_size() -> u16 {
    5000
}
fn default_ip_chunk_size() -> usize {
    256
}
fn default_tries() -> u8 {
    1
}

fn default_username_file() -> String {
    "usernames.txt".to_string()
}

fn default_password_file() -> String {
    "passwords.txt".to_string()
}

fn default_max_attempts() -> usize {
    1000
}

fn default_bruteforce_delay() -> u64 {
    500
}


/// Сообщения клиента → сервера
#[derive(Debug, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ClientMessage {
    StartScan(ScanParams),
    Pause,
    Resume,
    Stop,
}

/// Типы «находок» (результаты постобработки открытых сокетов)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    HttpService,
    SshService,
    FtpService,
    GenericService,
    RtspService,
    VncService,
    RdpService,
    RedisService,
    MongoService,
    DockerService,
    ElasticService,
    TelnetService,
    SnmpService,
    ModbusService,
}

impl FindingKind {
    pub fn label(&self) -> &'static str {
        match self {
            FindingKind::HttpService => "http",
            FindingKind::SshService => "ssh",
            FindingKind::FtpService => "ftp",
            FindingKind::GenericService => "generic",
            FindingKind::RtspService => "rtsp",
            FindingKind::VncService => "vnc",
            FindingKind::RdpService => "rdp",
            FindingKind::RedisService => "redis",
            FindingKind::MongoService => "mongo",
            FindingKind::DockerService => "docker",
            FindingKind::ElasticService => "elastic",
            FindingKind::TelnetService => "telnet",
            FindingKind::SnmpService => "snmp",
            FindingKind::ModbusService => "modbus"
        }
    }
}

/// Описание найденного сервиса
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub addr: String,
    pub kind: FindingKind,
    pub title: Option<String>,
    pub details: Option<String>,
}

/// Сообщения сервера → клиента
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Status { text: String },
    Error { error: String },
    Port { addr: String },
    Progress { completed: u64, total: u64 },
    Finding { finding: Finding },
    Finished,
    Snapshot {
        running: bool,
        paused: bool,
        status: String,
        completed: u64,
        total: u64,
    },
}

