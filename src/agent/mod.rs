pub mod upstream;
pub mod config;

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::Framed;

use crate::protocol::{Frame, FrameCodec, FrameFlag};

pub struct TunnelAgent {
    pub config: config::AgentConfig,
}

impl TunnelAgent {
    pub fn new(config: config::AgentConfig) -> Self {
        Self { config }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        loop {
            match self.connect_and_run().await {
                Ok(()) => tracing::info!("connection closed, reconnecting..."),
                Err(e) => tracing::warn!("connection error: {}, reconnecting...", e),
            }
            tokio::time::sleep(std::time::Duration::from_secs(
                self.config.reconnect_interval_sec,
            ))
            .await;
        }
    }

    async fn connect_and_run(&self) -> anyhow::Result<()> {
        let stream = TcpStream::connect(&self.config.server_addr).await?;
        let mut framed = Framed::new(stream, FrameCodec);

        framed
            .send(Frame::register(&self.config.token, &self.config.name))
            .await?;

        let ack = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            framed.next(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("registration timeout"))?
        .ok_or_else(|| anyhow::anyhow!("connection closed"))??;

        if ack.flag != FrameFlag::RegisterAck {
            anyhow::bail!("expected RegisterAck, got {:?}", ack.flag);
        }

        if ack.payload.is_empty() || ack.payload[0] != 1 {
            let msg = String::from_utf8_lossy(&ack.payload[1..]);
            anyhow::bail!("registration rejected: {}", msg);
        }

        tracing::info!("registered as {}", self.config.name);

        let (tx, mut rx) = mpsc::channel::<Frame>(256);
        let upstream_addr = Arc::new(self.config.upstream_addr.clone());

        loop {
            tokio::select! {
                frame = framed.next() => {
                    let frame = match frame {
                        Some(Ok(f)) => f,
                        Some(Err(e)) => return Err(e.into()),
                        None => return Ok(()),
                    };
                    match frame.flag {
                        FrameFlag::Heartbeat => {
                            framed.send(Frame::heartbeat_ack()).await?;
                        }
                        FrameFlag::HeartbeatAck => {}
                        FrameFlag::RequestStart => {
                            let stream_id = frame.stream_id;
                            let payload = frame.payload.clone();
                            let tx = tx.clone();
                            let addr = upstream_addr.clone();
                            tokio::spawn(async move {
                                let resp = upstream::forward_to_upstream(&addr, &payload).await;
                                match resp {
                                    Ok(data) => {
                                        let _ = tx.send(Frame::response_start(
                                            stream_id,
                                            bytes::Bytes::from(data),
                                        )).await;
                                        let _ = tx.send(Frame::response_end(stream_id)).await;
                                    }
                                    Err(_) => {
                                        let _ = tx.send(Frame::reset(stream_id)).await;
                                    }
                                }
                            });
                        }
                        FrameFlag::Reset => {}
                        _ => {}
                    }
                }
                frame = rx.recv() => {
                    match frame {
                        Some(f) => framed.send(f).await?,
                        None => return Ok(()),
                    }
                }
            }
        }
    }
}
