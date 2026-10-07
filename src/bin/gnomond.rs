use clap::Parser;
#[derive(Parser)]
#[command(version, about = "RFC 10049 UDP/TCP Roughtime daemon")]
struct Args {
    #[arg(short, long, default_value = "/etc/gnomon/gnomon.toml")]
    config: std::path::PathBuf,
    /// Validate configuration, key material, delegation, and current clock, then exit.
    #[arg(long)]
    check: bool,
}
#[tokio::main(worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let c = gnomon::server::Config::read(&args.config)?;
    if args.check {
        let id = c.identity()?;
        gnomon::server::check_clock(&c)?;
        let now = gnomon::server::unix_time()?;
        anyhow::ensure!(now >= id.mint && now <= id.maxt, "delegation not valid now");
        println!("configuration, delegation, and clock valid");
        return Ok(());
    }
    gnomon::server::run(c).await
}
