use clap::Parser;
#[derive(Parser)]
#[command(version, about = "RFC 10049 UDP/TCP Roughtime daemon")]
struct Args {
    /// Config file [default: /etc/gnomon/gnomon.toml if it exists]. Any setting
    /// can instead be given as GNOMON_ plus the upper-case field name, which
    /// overrides the file.
    #[arg(short, long, env = "GNOMON_CONFIG")]
    config: Option<std::path::PathBuf>,
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
    let default = std::path::Path::new(gnomon::server::DEFAULT_CONFIG);
    let path = match args.config {
        Some(path) => Some(path),
        None => default.try_exists()?.then(|| default.to_path_buf()),
    };
    let c = gnomon::server::Config::load(path.as_deref())?;
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
