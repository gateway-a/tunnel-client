use clap::Parser;
use tracing_subscriber::EnvFilter;

use tunnel::agent::config::AgentConfig;
use tunnel::agent::TunnelAgent;

#[derive(Parser)]
#[command(name = "tunnel-agent")]
struct Args {
    #[arg(long)]
    config: Option<String>,
    #[arg(long)]
    server: Option<String>,
    #[arg(long)]
    token: Option<String>,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    upstream: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let args = Args::parse();

    let config = if let Some(path) = args.config {
        AgentConfig::load(&path)?
    } else {
        AgentConfig {
            server_addr: args.server.unwrap_or_else(|| "127.0.0.1:9100".to_string()),
            token: args.token.expect("--token required"),
            name: args.name.expect("--name required"),
            upstream_addr: args.upstream.unwrap_or_else(|| "127.0.0.1:3000".to_string()),
            reconnect_interval_sec: 3,
        }
    };

    let agent = TunnelAgent::new(config);
    agent.run().await
}
