use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use axum::{
    extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use crate::model::{ClientMessage, ServerMessage};
use crate::scan::run_scan_job;

/// HTTP → WebSocket апгрейд
pub async fn ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(handle_socket)
}

/// Обработка одного WebSocket-подключения
async fn handle_socket(stream: WebSocket) {
    let (mut sender, mut receiver) = stream.split();

    // Канал для отправки сообщений из сканера → клиенту
    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<String>();

    // Флаг паузы, общий для этого соединения
    let pause_flag = Arc::new(AtomicBool::new(false));

    // Таск отправки сообщений по WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg_text) = rx_out.recv().await {
            if sender.send(WsMessage::Text(msg_text)).await.is_err() {
                break;
            }
        }
    });

    let stop_flag  = Arc::new(AtomicBool::new(false));

    // Основной цикл: принимаем команды клиента
    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            WsMessage::Text(text) => {
                match serde_json::from_str::<ClientMessage>(&text) {
                    Ok(ClientMessage::StartScan(params)) => {
                        let tx = tx_out.clone();
                        let pause = pause_flag.clone();
                        pause.store(false, Ordering::SeqCst);
                        let stop = stop_flag.clone();
                        stop.store(false, Ordering::SeqCst);

                        // Запускаем новый скан
                        tokio::spawn(async move {
                            run_scan_job(params, tx, pause, stop).await;
                        });
                    }
                    Ok(ClientMessage::Pause) => {
                        pause_flag.store(true, Ordering::SeqCst);
                        let _ = tx_out.send(
                            serde_json::to_string(&ServerMessage::Status {
                                text: "Сканирование поставлено на паузу".into(),
                            })
                            .unwrap(),
                        );
                    }
                    Ok(ClientMessage::Resume) => {
                        pause_flag.store(false, Ordering::SeqCst);
                        let _ = tx_out.send(
                            serde_json::to_string(&ServerMessage::Status {
                                text: "Сканирование продолжено".into(),
                            })
                            .unwrap(),
                        );
                    }
                    Ok(ClientMessage::Stop) => {
                        stop_flag.store(true, Ordering::SeqCst);
                        let _ = tx_out.send(
                            serde_json::to_string(&ServerMessage::Status {
                                text: "Сканирование остановлено".into(),
                            })
                            .unwrap(),
                        );
                    }
                    Err(err) => {
                        let _ = tx_out.send(
                            serde_json::to_string(&ServerMessage::Error {
                                error: format!("Неверный формат сообщения: {err}"),
                            })
                            .unwrap(),
                        );
                    }
                }
            }
            WsMessage::Close(_) => break,
            _ => {}
        }
    }

    drop(tx_out);
    let _ = send_task.await;
}
