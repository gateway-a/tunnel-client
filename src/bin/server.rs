use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "tunnel-server")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:9100")]
    listen: String,
    #[arg(long, default_value = "0.0.0.0:9101")]
    api: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let args = Args::parse();
    let server = tunnel::server::TunnelServer::new(args.listen, args.api);
    server.run().await
}
