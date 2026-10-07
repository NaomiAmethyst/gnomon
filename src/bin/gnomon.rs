use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand, ValueEnum};
use gnomon::{
    client::{Address, Backoff, Server, ServerList},
    crypto::{self, VerifiedTime},
    evidence::{Evidence, inconsistency},
    keys,
};
use rand::{RngCore, rngs::OsRng, seq::SliceRandom};
use std::{path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    version,
    about = "Authenticated RFC 10049 Roughtime client and offline key tools"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, ValueEnum)]
enum Transport {
    Auto,
    Udp,
    Tcp,
}
#[derive(Subcommand)]
enum Command {
    /// Generate a private seed and print its base64 public key. Never overwrites.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign an online public key with an offline long-term root seed.
    Delegate {
        #[arg(long)]
        root_key: PathBuf,
        #[arg(long)]
        online_public_key: String,
        #[arg(long)]
        mint: u64,
        #[arg(long)]
        maxt: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Query one pinned server. This alone cannot detect a dishonest server.
    Query {
        #[arg(long)]
        server: String,
        #[arg(long)]
        public_key: String,
        #[arg(long, value_enum, default_value = "auto")]
        transport: Transport,
        #[arg(long, default_value_t = 3)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 4)]
        attempts: u32,
    },
    /// Randomly select at least three identities and query twice in causal order.
    Measure {
        #[arg(long)]
        servers: PathBuf,
        #[arg(long, default_value_t = 3)]
        count: usize,
        #[arg(long, default_value_t = 3)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 4)]
        attempts: u32,
        /// Evidence is saved on success or malfeasance; never overwritten.
        #[arg(long, default_value = "gnomon-evidence.json")]
        evidence: PathBuf,
    },
    /// Verify signatures, request binding, chaining, and causal ordering offline.
    VerifyEvidence { file: PathBuf },
}
fn random() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .context("operating-system random generator")?;
    Ok(bytes)
}
fn limits(timeout: u64, attempts: u32) -> Result<Duration> {
    ensure!(
        (1..=60).contains(&timeout) && (1..=32).contains(&attempts),
        "timeout must be 1..60 and attempts 1..32"
    );
    Ok(Duration::from_secs(timeout))
}
fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    ensure!(
        std::fs::metadata(path)?.len() <= 24 * 1024 * 1024,
        "JSON file too large"
    );
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
struct Chain {
    report: Evidence,
    times: Vec<VerifiedTime>,
    latest_rtt: Duration,
    inconsistency: Option<(usize, usize)>,
}
/// Queries each server twice in the same order, chaining every nonce to the
/// previous response. Stops at the first authenticated causal inconsistency.
async fn measure(servers: &[Server], timeout: Duration, attempts: u32) -> Result<Chain> {
    let mut chain = Chain {
        report: Evidence::default(),
        times: Vec::new(),
        latest_rtt: Duration::ZERO,
        inconsistency: None,
    };
    let mut previous = None::<Vec<u8>>;
    let mut backoffs: Vec<_> = servers.iter().map(|_| Backoff::default()).collect();
    for _ in 0..2 {
        for (s, backoff) in servers.iter().zip(&mut backoffs) {
            let rand = random()?;
            let nonce = match &previous {
                Some(prev) => crypto::hash(&[prev, &rand]),
                None => rand,
            };
            let key = gnomon::client::decode_key(&s.public_key)?;
            let request = crypto::request(&nonce, &key)?;
            let m = gnomon::client::query(&s.addresses, &key, &request, timeout, attempts, backoff)
                .await
                .with_context(|| format!("query {}", s.name))?;
            chain.report.push(
                previous.as_ref().map(|_| &rand),
                &key,
                &request,
                &m.response,
            );
            previous = Some(m.response);
            chain.latest_rtt = m.round_trip;
            chain.times.push(m.time);
            chain.inconsistency = inconsistency(&chain.times);
            if chain.inconsistency.is_some() {
                return Ok(chain);
            }
        }
    }
    Ok(chain)
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Keygen { out } => {
            let k = keys::create(&out)?;
            println!("{}", STANDARD.encode(k.verifying_key().to_bytes()));
        }
        Command::Delegate {
            root_key,
            online_public_key,
            mint,
            maxt,
            out,
        } => {
            let root = keys::load(&root_key)?;
            let cert = crypto::certificate(
                &root,
                &gnomon::client::decode_key(&online_public_key)?,
                mint,
                maxt,
            )?;
            keys::write_new(&out, &cert, false)?;
        }
        Command::Query {
            server,
            public_key,
            transport,
            timeout_seconds,
            attempts,
        } => {
            let timeout = limits(timeout_seconds, attempts)?;
            let key = gnomon::client::decode_key(&public_key)?;
            let protocols = match transport {
                Transport::Auto => vec!["udp", "tcp"],
                Transport::Udp => vec!["udp"],
                Transport::Tcp => vec!["tcp"],
            };
            let addresses = protocols
                .into_iter()
                .map(|protocol| Address {
                    protocol: protocol.into(),
                    address: server.clone(),
                })
                .collect::<Vec<_>>();
            let request = crypto::request(&random()?, &key)?;
            let m = gnomon::client::query(
                &addresses,
                &key,
                &request,
                timeout,
                attempts,
                &mut Backoff::default(),
            )
            .await?;
            println!(
                "{}",
                serde_json::json!({"midpoint":m.time.midpoint,"radius":m.time.radius,"roundTripSeconds":m.round_trip.as_secs_f64(),"earliestAtReceipt":m.time.lower(),"latestAtReceipt":m.time.upper()+m.round_trip.as_secs_f64().ceil() as i128})
            );
        }
        Command::Measure {
            servers,
            count,
            timeout_seconds,
            attempts,
            evidence,
        } => {
            let timeout = limits(timeout_seconds, attempts)?;
            let mut list: ServerList = read_json(&servers)?;
            list.validate()?;
            list.servers.shuffle(&mut OsRng);
            let mut seen = std::collections::HashSet::new();
            list.servers.retain(|s| seen.insert(s.public_key.clone()));
            ensure!(
                count >= 3 && count <= list.servers.len(),
                "need at least {count} distinct pinned identities (minimum three)"
            );
            list.servers.truncate(count);
            // Claim the output before querying so a malfeasance proof always has
            // somewhere to go. Remove it if no evidence is produced.
            let mut output = keys::create_new(&evidence, false)?;
            let chain = match measure(&list.servers, timeout, attempts).await {
                Ok(chain) => chain,
                Err(error) => {
                    drop(output);
                    let _ = std::fs::remove_file(&evidence);
                    return Err(error);
                }
            };
            let saved = serde_json::to_vec_pretty(&chain.report)
                .map_err(anyhow::Error::from)
                .and_then(|json| keys::write_all(&mut output, &json));
            if let Some((earlier, later)) = chain.inconsistency {
                match saved {
                    Ok(()) => anyhow::bail!(
                        "authenticated causal inconsistency between responses {earlier} and {later}; evidence saved to {}",
                        evidence.display()
                    ),
                    Err(error) => anyhow::bail!(
                        "authenticated causal inconsistency between responses {earlier} and {later}, but saving evidence to {} failed: {error:#}",
                        evidence.display()
                    ),
                }
            }
            saved?;
            let last = chain.times.last().context("empty measurement")?;
            println!(
                "{}",
                serde_json::json!({
                    "responses": chain.times.len(),
                    "earliestAtReceipt": chain.times.iter().map(|t| t.lower()).max(),
                    "latestAtReceipt": last.upper() + chain.latest_rtt.as_secs_f64().ceil() as i128,
                    "evidence": evidence,
                })
            );
        }
        Command::VerifyEvidence { file } => {
            let evidence: Evidence = read_json(&file)?;
            let times = evidence.verify()?;
            println!(
                "{}",
                serde_json::json!({"authenticatedResponses":times.len(),"causalInconsistency":inconsistency(&times)})
            );
        }
    }
    Ok(())
}
