// Copyright (c) 2022 Yuki Kishimoto
// Distributed under the MIT software license

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use nostr_sdk_base::{ClientMessage, RelayMessage};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use url::Url;

mod network;
pub mod pool;
mod socks;

use self::pool::RelayPoolEvent;

#[cfg(feature = "blocking")]
use crate::new_current_thread;

/// Relay connection status
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RelayStatus {
    /// Relay initialized
    Initialized,
    /// Relay connected
    Connected,
    /// Connecting
    Connecting,
    /// Relay disconnected, will retry to connect again
    Disconnected,
    /// Relay completly disconnected
    Terminated,
}

#[derive(Debug)]
enum RelayEvent {
    SendMsg(Box<ClientMessage>),
    Ping,
    Close,
    Terminate,
}

#[derive(Clone)]
pub struct Relay {
    url: Url,
    proxy: Option<SocketAddr>,
    status: Arc<Mutex<RelayStatus>>,
    pool_sender: Sender<RelayPoolEvent>,
    relay_sender: Sender<RelayEvent>,
    relay_receiver: Arc<Mutex<Receiver<RelayEvent>>>,
}

impl Relay {
    /// Create new `Relay`
    pub fn new(
        url: &str,
        pool_sender: Sender<RelayPoolEvent>,
        proxy: Option<SocketAddr>,
    ) -> Result<Self> {
        let (relay_sender, relay_receiver) = mpsc::channel::<RelayEvent>(64);

        Ok(Self {
            url: Url::from_str(url)?,
            proxy,
            status: Arc::new(Mutex::new(RelayStatus::Initialized)),
            pool_sender,
            relay_sender,
            relay_receiver: Arc::new(Mutex::new(relay_receiver)),
        })
    }

    /// Get relay url
    pub fn url(&self) -> Url {
        self.url.clone()
    }

    async fn status(&self) -> RelayStatus {
        let status = self.status.lock().await;
        status.clone()
    }

    async fn set_status(&self, status: RelayStatus) {
        let mut s = self.status.lock().await;
        *s = status;
    }

    /// Connect to relay and keep alive connection
    pub async fn connect(&self) {
        if let RelayStatus::Initialized | RelayStatus::Terminated = self.status().await {
            // Update relay status
            self.set_status(RelayStatus::Disconnected).await;

            let relay = self.clone();
            let connection_thread = async move {
                loop {
                    // Check status
                    match relay.status().await {
                        RelayStatus::Disconnected => relay.try_connect().await,
                        RelayStatus::Terminated => break,
                        _ => (),
                    };

                    // TODO: if disconnected and connected again, get subscription filters from store (sled or something else) and send it again

                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            };

            #[cfg(feature = "blocking")]
            match new_current_thread() {
                Ok(rt) => {
                    std::thread::spawn(move || {
                        rt.block_on(async move { connection_thread.await });
                        rt.shutdown_timeout(Duration::from_millis(100));
                    });
                }
                Err(e) => log::error!("Impossible to create new thread: {:?}", e),
            };

            #[cfg(not(feature = "blocking"))]
            tokio::task::spawn(connection_thread);
        }
    }

    async fn try_connect(&self) {
        let url: String = self.url.to_string();

        self.set_status(RelayStatus::Connecting).await;
        log::debug!("Connecting to {}", url);

        match network::get_connection(&self.url, self.proxy).await {
            Ok((mut ws_tx, mut ws_rx)) => {
                self.set_status(RelayStatus::Connected).await;
                log::info!("Connected to {}", url);

                let relay = self.clone();
                let func_relay_event = async move {
                    log::debug!("Relay Event Thread Started");
                    while let Some(relay_event) = relay.relay_receiver.lock().await.recv().await {
                        match relay_event {
                            RelayEvent::SendMsg(msg) => {
                                log::trace!("Sending message {}", msg.to_json());
                                if let Err(e) = ws_tx.send(Message::Text(msg.to_json())).await {
                                    log::error!("RelayEvent::SendMsg error: {:?}", e);
                                };
                            }
                            RelayEvent::Ping => {
                                if let Err(e) = ws_tx.send(Message::Ping(Vec::new())).await {
                                    log::error!("Ping error: {:?}", e);
                                    break;
                                }
                            }
                            RelayEvent::Close => {
                                if let Err(e) = ws_tx.close().await {
                                    log::error!("RelayEvent::Close error: {:?}", e);
                                };
                                relay.set_status(RelayStatus::Disconnected).await;
                                log::info!("Disconnected from {}", url);
                                break;
                            }
                            RelayEvent::Terminate => {
                                if let Err(e) = ws_tx.close().await {
                                    log::error!("RelayEvent::Close error: {:?}", e);
                                };
                                relay.set_status(RelayStatus::Terminated).await;
                                log::info!("Completely disconnected from {}", url);
                                break;
                            }
                        }
                    }
                };

                #[cfg(feature = "blocking")]
                match new_current_thread() {
                    Ok(rt) => {
                        std::thread::spawn(move || {
                            rt.block_on(async move { func_relay_event.await });
                            rt.shutdown_timeout(Duration::from_millis(100));
                        });
                    }
                    Err(e) => log::error!("Impossible to create new thread: {:?}", e),
                };

                #[cfg(not(feature = "blocking"))]
                tokio::task::spawn(func_relay_event);

                let relay = self.clone();
                let func_relay_msg = async move {
                    log::debug!("Relay Message Thread Started");
                    while let Some(msg_res) = ws_rx.next().await {
                        if let Ok(msg) = msg_res {
                            let data: Vec<u8> = msg.into_data();

                            match String::from_utf8(data) {
                                Ok(data) => match RelayMessage::from_json(&data) {
                                    Ok(msg) => {
                                        log::trace!("Received data: {}", &msg.to_json());
                                        if let Err(err) = relay
                                            .pool_sender
                                            .send(RelayPoolEvent::ReceivedMsg {
                                                relay_url: relay.url(),
                                                msg,
                                            })
                                            .await
                                        {
                                            log::error!(
                                                "Impossible to send ReceivedMsg to pool: {}",
                                                &err
                                            );
                                        }
                                    }
                                    Err(err) => {
                                        log::error!("{}", err);
                                    }
                                },
                                Err(err) => log::error!("{}", err),
                            }
                        }
                    }

                    if relay.status().await != RelayStatus::Terminated {
                        if let Err(err) = relay.disconnect().await {
                            log::error!("Impossible to disconnect {}: {}", relay.url, err);
                        }
                    }
                };

                #[cfg(feature = "blocking")]
                match new_current_thread() {
                    Ok(rt) => {
                        std::thread::spawn(move || {
                            rt.block_on(async move { func_relay_msg.await });
                            rt.shutdown_timeout(Duration::from_millis(100));
                        });
                    }
                    Err(e) => log::error!("Impossible to create new thread: {:?}", e),
                };

                #[cfg(not(feature = "blocking"))]
                tokio::task::spawn(func_relay_msg);

                // Ping thread
                let relay = self.clone();
                let func_relay_ping = async move {
                    log::debug!("Relay Ping Thread Started");

                    loop {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        match relay.ping().await {
                            Ok(_) => log::debug!("Ping {}", relay.url),
                            Err(err) => {
                                log::error!("Impossible to ping {}: {}", relay.url, err);
                                break;
                            }
                        }
                    }

                    if relay.status().await != RelayStatus::Terminated {
                        if let Err(err) = relay.disconnect().await {
                            log::error!("Impossible to disconnect {}: {}", relay.url, err);
                        }
                    }
                };

                #[cfg(feature = "blocking")]
                match new_current_thread() {
                    Ok(rt) => {
                        std::thread::spawn(move || {
                            rt.block_on(async move { func_relay_ping.await });
                            rt.shutdown_timeout(Duration::from_millis(100));
                        });
                    }
                    Err(e) => log::error!("Impossible to create new thread: {:?}", e),
                };

                #[cfg(not(feature = "blocking"))]
                tokio::task::spawn(func_relay_ping);
            }
            Err(err) => {
                self.set_status(RelayStatus::Disconnected).await;
                log::error!("Impossible to connect to {}: {}", url, err);
            }
        };
    }

    async fn send_relay_event(&self, relay_msg: RelayEvent) -> Result<()> {
        Ok(self.relay_sender.send(relay_msg).await?)
    }

    /// Ping relay
    async fn ping(&self) -> Result<()> {
        self.send_relay_event(RelayEvent::Ping).await
    }

    /// Disconnect from relay and set status to 'Disconnected'
    async fn disconnect(&self) -> Result<()> {
        self.send_relay_event(RelayEvent::Close).await
    }

    /// Disconnect from relay and set status to 'Terminated'
    pub async fn terminate(&self) -> Result<()> {
        self.send_relay_event(RelayEvent::Terminate).await
    }

    /// Send msg to relay
    pub async fn send_msg(&self, msg: ClientMessage) -> Result<()> {
        self.send_relay_event(RelayEvent::SendMsg(Box::new(msg)))
            .await
    }
}