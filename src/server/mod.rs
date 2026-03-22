pub mod registry;
pub mod relay;
pub mod api;

use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

use crate::server::registry::TunnelRegistry;

pub struct TunnelServer {
    pub registry: Arc<TunnelRegistry>,
    pub listen_addr: String,
    pub api_addr: String,
}

impl TunnelServer {
    pub fn new(listen_addr: String, api_addr: String) -> Self {
        Self {
            registry: Arc::new(TunnelRegistry::new()),
            listen_addr,
            api_addr,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let registry = self.registry.clone();

        let api_registry = registry.clone();
        let api_addr = self.api_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = api::serve(api_addr, api_registry).await {
                tracing::error!("api server error: {}", e);
            }
        });

        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!("tunnel server listening on {}", self.listen_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            let reg = registry.clone();
            tokio::spawn(async move {
                if let Err(e) = relay::handle_agent_connection(stream, addr, reg).await {
                    tracing::warn!("agent {} disconnected: {}", addr, e);
                }
            });
        }
    }
}
