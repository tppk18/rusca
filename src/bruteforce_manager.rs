use std::net::SocketAddr;
use tokio::sync::mpsc::UnboundedSender;

use crate::model::FindingKind;
use crate::bruteforce::{BruteforceConfig, BruteforceModule, SSHBruteforceModule, RTSPBruteforceModule, FTPBruteforceModule};

pub struct BruteforceManager {
    modules: Vec<Box<dyn BruteforceModule>>,
}

impl BruteforceManager {
    pub fn new(tx: UnboundedSender<String>, config: BruteforceConfig) -> Self {
        let mut modules: Vec<Box<dyn BruteforceModule>> = Vec::new();
        
        // Добавляем модуль SSH брутфорса
        //modules.push(Box::new(SSHBruteforceModule::new(tx.clone(), config.clone())));
        modules.push(Box::new(RTSPBruteforceModule::new(tx.clone(), config.clone())));
        modules.push(Box::new(FTPBruteforceModule::new(tx.clone(), config.clone())));
        // Здесь будем добавлять другие модули: FTP, HTTP и т.д.
        
        Self { modules }
    }

    pub fn start_bruteforce(&self, addr: SocketAddr, banner: String, service_kind: FindingKind) {
        for module in &self.modules {
            if module.supports(service_kind.clone()) {
                module.start_bruteforce(addr, banner);
                break;
            }
        }
    }
}