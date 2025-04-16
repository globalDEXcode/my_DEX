//////////////////////////////////////////////////
/// my_DEX/src/network/tcp.rs (verschlüsselte Version)
//////////////////////////////////////////////////

use tokio::net::{TcpListener, TcpStream};
use crate::network::secure_channel::SecureChannel;
use crate::network::security_monitor::SecurityMonitor;
use crate::protocol::{P2PMessage, serialize_message, deserialize_message};
use std::net::SocketAddr;
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

pub struct NetworkManager {
    pub address: SocketAddr,
}

impl NetworkManager {
    pub async fn new(address: SocketAddr) -> Self {
        NetworkManager { address }
    }

    pub async fn start_listener(&self) -> Result<()> {
        let listener = TcpListener::bind(self.address).await?;
        println!("🔐 Listening securely on {}", self.address);
        loop {
            let (stream, addr) = listener.accept().await?;
            let monitor = Arc::new(SecurityMonitor::new());
            tokio::spawn(Self::handle_connection(stream, monitor, addr));
        }
    }

    async fn handle_connection(stream: TcpStream, monitor: Arc<SecurityMonitor>, addr: SocketAddr) {
        match SecureChannel::accept_from_stream(stream, "Noise_XX_25519_ChaChaPoly_BLAKE2s", monitor.clone()).await {
            Ok(mut secure) => {
                match secure.receive().await {
                    Ok(bytes) => {
                        if let Some(msg) = deserialize_message(&bytes) {
                            println!("✅ Nachricht von {}: {:?}", addr, msg);
                        } else {
                            println!("⚠️ Nachricht von {} konnte nicht deserialisiert werden", addr);
                        }
                    }
                    Err(e) => {
                        println!("❌ Fehler beim Empfang von {}: {:?}", addr, e);
                    }
                }
            }
            Err(e) => println!("❌ Fehler beim Handshake mit {}: {:?}", addr, e),
        }
    }

    pub async fn send_message(&self, addr: SocketAddr, msg: P2PMessage) -> Result<()> {
        let stream = TcpStream::connect(addr).await?;
        let monitor = Arc::new(SecurityMonitor::new());
        let mut secure = SecureChannel::connect_stream(stream, "Noise_XX_25519_ChaChaPoly_BLAKE2s", monitor).await?;

        let data = serialize_message(&msg);
        secure.send(&data).await?;
        Ok(())
    }
}
