use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::protocol::Frame;

pub struct TunnelSession {
    pub name: String,
    pub token: String,
    pub tx: mpsc::Sender<Frame>,
    pub next_stream_id: AtomicU32,
    pub active_streams: DashMap<u32, mpsc::Sender<Bytes>>,
    pub connected_at: u64,
}

impl TunnelSession {
    pub fn next_stream(&self) -> u32 {
        self.next_stream_id.fetch_add(2, Ordering::Relaxed)
    }
}

pub struct TunnelRegistry {
    sessions: DashMap<String, Arc<TunnelSession>>,
    tokens: DashMap<String, String>,
}

impl Default for TunnelRegistry {
    fn default() -> Self { Self::new() }
}

impl TunnelRegistry {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            tokens: DashMap::new(),
        }
    }

    pub fn create_tunnel(&self, name: &str) -> String {
        let token = generate_token();
        self.tokens.insert(token.clone(), name.to_string());
        token
    }

    pub fn validate_token(&self, token: &str) -> Option<String> {
        self.tokens.get(token).map(|v| v.value().clone())
    }

    pub fn register_session(&self, name: &str, token: &str, tx: mpsc::Sender<Frame>) -> Arc<TunnelSession> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session = Arc::new(TunnelSession {
            name: name.to_string(),
            token: token.to_string(),
            tx,
            next_stream_id: AtomicU32::new(1),
            active_streams: DashMap::new(),
            connected_at: now,
        });

        self.sessions.insert(name.to_string(), session.clone());
        session
    }

    pub fn remove_session(&self, name: &str) {
        self.sessions.remove(name);
    }

    pub fn get_session(&self, name: &str) -> Option<Arc<TunnelSession>> {
        self.sessions.get(name).map(|v| v.value().clone())
    }

    pub fn revoke_tunnel(&self, name: &str) -> bool {
        self.sessions.remove(name);
        let mut removed = false;
        self.tokens.retain(|_, v| {
            if v == name {
                removed = true;
                false
            } else {
                true
            }
        });
        removed
    }

    pub fn list_tunnels(&self) -> Vec<TunnelInfo> {
        let mut result = Vec::new();

        let active: DashMap<String, bool> = DashMap::new();
        for entry in self.sessions.iter() {
            active.insert(entry.key().clone(), true);
        }

        for entry in self.tokens.iter() {
            let name = entry.value().clone();
            let is_connected = active.contains_key(&name);
            let connected_at = self.sessions.get(&name).map(|s| s.connected_at);
            result.push(TunnelInfo {
                name,
                token: mask_token(entry.key()),
                connected: is_connected,
                connected_at,
            });
        }

        result
    }

    pub fn tunnel_status(&self, name: &str) -> Option<TunnelStatus> {
        let has_token = self.tokens.iter().any(|e| e.value() == name);
        if !has_token {
            return None;
        }

        let session = self.sessions.get(name);
        Some(TunnelStatus {
            name: name.to_string(),
            connected: session.is_some(),
            active_streams: session.as_ref().map(|s| s.active_streams.len()).unwrap_or(0),
            connected_at: session.as_ref().map(|s| s.connected_at),
        })
    }
}

#[derive(serde::Serialize)]
pub struct TunnelInfo {
    pub name: String,
    pub token: String,
    pub connected: bool,
    pub connected_at: Option<u64>,
}

#[derive(serde::Serialize)]
pub struct TunnelStatus {
    pub name: String,
    pub connected: bool,
    pub active_streams: usize,
    pub connected_at: Option<u64>,
}

fn generate_token() -> String {
    use rand::Rng;
    use sha2::{Sha256, Digest};
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 32] = rng.gen();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(random_bytes);
    hasher.update(ts.to_le_bytes());
    hex::encode(hasher.finalize())
}

fn mask_token(token: &str) -> String {
    if token.len() <= 8 {
        return "*".repeat(token.len());
    }
    format!("{}...{}", &token[..4], &token[token.len() - 4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_validate_token() {
        let reg = TunnelRegistry::new();
        let token = reg.create_tunnel("test-app");
        assert_eq!(token.len(), 64);
        assert_eq!(reg.validate_token(&token), Some("test-app".to_string()));
        assert_eq!(reg.validate_token("invalid"), None);
    }

    #[test]
    fn revoke_tunnel() {
        let reg = TunnelRegistry::new();
        let _token = reg.create_tunnel("test-app");
        assert!(reg.revoke_tunnel("test-app"));
        assert!(!reg.revoke_tunnel("nonexistent"));
    }

    #[test]
    fn list_tunnels() {
        let reg = TunnelRegistry::new();
        reg.create_tunnel("app-1");
        reg.create_tunnel("app-2");
        let list = reg.list_tunnels();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn mask_token_format() {
        assert_eq!(mask_token("abcdefghijklmnop"), "abcd...mnop");
        assert_eq!(mask_token("short"), "*****");
    }
}
