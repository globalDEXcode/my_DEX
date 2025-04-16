/////////////////////////////////////////////////////
/// my_DEX/src/network/handler.rs (verschlüsselt)
/////////////////////////////////////////////////////

use tokio::net::{TcpListener, TcpStream};
use crate::network::secure_channel::SecureChannel;
use crate::network::security_monitor::SecurityMonitor;
use std::sync::Arc;
use tokio::sync::mpsc;
use anyhow::Result;

pub struct P2PNetwork {
    pub peers: Vec<String>,
    pub message_sender: mpsc::Sender<String>,
}

impl P2PNetwork {
    pub async fn start_listener(address: &str, message_sender: mpsc::Sender<String>) -> Result<()> {
        let listener = TcpListener::bind(address).await?;
        println!("🔐 P2P-Netzwerk läuft auf {} (verschlüsselt)", address);

        loop {
            let (stream, _) = listener.accept().await?;
            let sender_clone = message_sender.clone();
            let monitor = Arc::new(SecurityMonitor::new());

            tokio::spawn(async move {
                match SecureChannel::accept_from_stream(stream, "Noise_XX_25519_ChaChaPoly_BLAKE2s", monitor).await {
                    Ok(mut secure) => {
                        match secure.receive().await {
                            Ok(data) => {
                                let msg = String::from_utf8_lossy(&data).to_string();
                                println!("📨 Nachricht empfangen: {}", msg);
                                sender_clone.send(msg).await.unwrap();
                            },
                            Err(e) => eprintln!("⚠ Fehler beim Empfang: {:?}", e),
                        }
                    },
                    Err(e) => eprintln!("❌ Fehler beim Verbindungsaufbau: {:?}", e),
                }
            });
        }
    }

    pub async fn send_message(&self, peer: &str, message: &str) -> Result<()> {
        let stream = TcpStream::connect(peer).await?;
        let monitor = Arc::new(SecurityMonitor::new());
        let mut secure = SecureChannel::connect_stream(stream, "Noise_XX_25519_ChaChaPoly_BLAKE2s", monitor).await?;
        secure.send(message.as_bytes()).await?;
        Ok(())
    }
}
