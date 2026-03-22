use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::Framed;

use crate::protocol::{Frame, FrameCodec, FrameFlag};
use crate::server::registry::TunnelRegistry;

pub async fn handle_agent_connection(
    stream: TcpStream,
    addr: SocketAddr,
    registry: Arc<TunnelRegistry>,
) -> anyhow::Result<()> {
    let mut framed = Framed::new(stream, FrameCodec);

    let frame = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        framed.next(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("registration timeout"))?
    .ok_or_else(|| anyhow::anyhow!("connection closed before registration"))??;

    if frame.flag != FrameFlag::Register {
        anyhow::bail!("expected Register frame, got {:?}", frame.flag);
    }

    let payload = String::from_utf8(frame.payload.to_vec())?;
    let (token, name) = payload
        .split_once('\0')
        .ok_or_else(|| anyhow::anyhow!("invalid register payload"))?;

    let expected_name = registry
        .validate_token(token)
        .ok_or_else(|| anyhow::anyhow!("invalid token"))?;

    if expected_name != name {
        framed
            .send(Frame::register_ack(false, "name mismatch"))
            .await?;
        anyhow::bail!("name mismatch: expected {}, got {}", expected_name, name);
    }

    let (tx, mut rx) = mpsc::channel::<Frame>(256);
    let session = registry.register_session(name, token, tx);

    tracing::info!("agent registered: {} from {}", name, addr);
    framed
        .send(Frame::register_ack(true, "registered"))
        .await?;

    let tunnel_name = session.name.clone();
    let reg_cleanup = registry.clone();

    let result = run_session(&mut framed, &mut rx, &session).await;

    reg_cleanup.remove_session(&tunnel_name);
    tracing::info!("agent disconnected: {}", tunnel_name);

    result
}

async fn run_session(
    framed: &mut Framed<TcpStream, FrameCodec>,
    rx: &mut mpsc::Receiver<Frame>,
    session: &Arc<crate::server::registry::TunnelSession>,
) -> anyhow::Result<()> {
    let heartbeat_interval = std::time::Duration::from_secs(15);
    let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
    heartbeat_timer.tick().await;

    loop {
        tokio::select! {
            frame = framed.next() => {
                let frame = match frame {
                    Some(Ok(f)) => f,
                    Some(Err(e)) => return Err(e.into()),
                    None => return Ok(()),
                };
                handle_agent_frame(frame, session).await?;
            }
            frame = rx.recv() => {
                match frame {
                    Some(f) => framed.send(f).await?,
                    None => return Ok(()),
                }
            }
            _ = heartbeat_timer.tick() => {
                framed.send(Frame::heartbeat()).await?;
            }
        }
    }
}

async fn handle_agent_frame(
    frame: Frame,
    session: &Arc<crate::server::registry::TunnelSession>,
) -> anyhow::Result<()> {
    match frame.flag {
        FrameFlag::HeartbeatAck => {}
        FrameFlag::Heartbeat => {
            let _ = session.tx.send(Frame::heartbeat_ack()).await;
        }
        FrameFlag::ResponseStart | FrameFlag::Data | FrameFlag::ResponseEnd => {
            if let Some(stream_tx) = session.active_streams.get(&frame.stream_id) {
                let _ = stream_tx.send(frame.payload.clone()).await;
            }
            if frame.flag == FrameFlag::ResponseEnd {
                session.active_streams.remove(&frame.stream_id);
            }
        }
        FrameFlag::Reset => {
            session.active_streams.remove(&frame.stream_id);
        }
        _ => {}
    }
    Ok(())
}

pub async fn relay_request(
    session: &Arc<crate::server::registry::TunnelSession>,
    request_data: Bytes,
) -> anyhow::Result<Vec<u8>> {
    let stream_id = session.next_stream();
    let (resp_tx, mut resp_rx) = mpsc::channel::<Bytes>(64);

    session.active_streams.insert(stream_id, resp_tx);

    session
        .tx
        .send(Frame::request_start(stream_id, request_data))
        .await
        .map_err(|_| anyhow::anyhow!("agent disconnected"))?;

    session
        .tx
        .send(Frame::request_end(stream_id))
        .await
        .map_err(|_| anyhow::anyhow!("agent disconnected"))?;

    let mut response = Vec::new();
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while let Some(chunk) = resp_rx.recv().await {
            if chunk.is_empty() {
                break;
            }
            response.extend_from_slice(&chunk);
        }
    });

    timeout
        .await
        .map_err(|_| anyhow::anyhow!("tunnel response timeout"))?;

    session.active_streams.remove(&stream_id);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handle_agent_frame_heartbeat() {
        let (tx, mut rx) = mpsc::channel(16);
        let session = Arc::new(crate::server::registry::TunnelSession {
            name: "test".to_string(),
            token: "tok".to_string(),
            tx,
            next_stream_id: std::sync::atomic::AtomicU32::new(1),
            active_streams: dashmap::DashMap::new(),
            connected_at: 0,
        });

        handle_agent_frame(Frame::heartbeat(), &session).await.unwrap();
        let ack = rx.recv().await.unwrap();
        assert_eq!(ack.flag, FrameFlag::HeartbeatAck);
    }

    #[tokio::test]
    async fn handle_agent_frame_response() {
        let (tx, _rx) = mpsc::channel(16);
        let session = Arc::new(crate::server::registry::TunnelSession {
            name: "test".to_string(),
            token: "tok".to_string(),
            tx,
            next_stream_id: std::sync::atomic::AtomicU32::new(1),
            active_streams: dashmap::DashMap::new(),
            connected_at: 0,
        });

        let (stream_tx, mut stream_rx) = mpsc::channel(16);
        session.active_streams.insert(5, stream_tx);

        handle_agent_frame(
            Frame::response_start(5, Bytes::from_static(b"HTTP/1.1 200 OK\r\n")),
            &session,
        )
        .await
        .unwrap();

        let chunk = stream_rx.recv().await.unwrap();
        assert_eq!(&chunk[..], b"HTTP/1.1 200 OK\r\n");

        handle_agent_frame(Frame::response_end(5), &session).await.unwrap();
        assert!(!session.active_streams.contains_key(&5));
    }
}
