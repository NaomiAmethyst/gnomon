use crate::{
    crypto::{VerifiedTime, verify_response},
    server::read_frame,
    wire::MAX_PACKET,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket, lookup_host},
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Address {
    pub protocol: String,
    pub address: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    pub name: String,
    pub version: u32,
    pub public_key_type: String,
    pub public_key: String,
    pub addresses: Vec<Address>,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct ServerList {
    pub servers: Vec<Server>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reports: Option<String>,
}
impl ServerList {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.servers.is_empty() && self.servers.len() <= 1024,
            "server list size out of range"
        );
        for s in &self.servers {
            ensure!(
                s.version >= 1 && s.public_key_type == "ed25519",
                "unsupported server {}",
                s.name
            );
            decode_key(&s.public_key)?;
            ensure!(
                !s.addresses.is_empty() && s.addresses.len() <= 32,
                "server addresses out of range"
            );
            for a in &s.addresses {
                ensure!(
                    a.protocol == "udp" || a.protocol == "tcp",
                    "unsupported transport"
                );
                ensure!(
                    !a.address.contains('%'),
                    "IPv6 zone identifiers are not permitted"
                );
                let (host, port) = a
                    .address
                    .rsplit_once(':')
                    .context("address must include port")?;
                ensure!(
                    !host.is_empty() && port.parse::<u16>().is_ok(),
                    "invalid address"
                );
                if host.starts_with('[') {
                    ensure!(
                        host.ends_with(']')
                            && host[1..host.len() - 1]
                                .parse::<std::net::Ipv6Addr>()
                                .is_ok(),
                        "invalid IPv6 address"
                    );
                } else {
                    ensure!(
                        !host.contains(':') && !host.contains(['/', ' ', '[', ']']),
                        "invalid host"
                    );
                }
            }
        }
        for url in self.sources.iter().chain(self.reports.iter()) {
            ensure!(
                url.starts_with("https://") && url.len() > 8,
                "list URLs must use HTTPS"
            );
        }
        Ok(())
    }
}
pub fn decode_key(value: &str) -> Result<[u8; 32]> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    Ok(crate::wire::fixed(
        &STANDARD
            .decode(value)
            .context("invalid base64 public key")?,
    )?)
}
pub fn retry_interval(failures: u32) -> Duration {
    Duration::from_secs_f64(
        1.5f64
            .powi(failures.saturating_sub(1).min(100) as i32)
            .min(86400.0),
    )
}
#[derive(Debug)]
pub struct Measurement {
    pub time: VerifiedTime,
    pub response: Vec<u8>,
    pub round_trip: Duration,
}
#[derive(Default)]
pub struct Backoff {
    failures: u32,
    retry_after: Option<tokio::time::Instant>,
}
impl Backoff {
    pub fn failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        self.retry_after = Some(tokio::time::Instant::now() + retry_interval(self.failures));
    }
    async fn wait(&self) {
        if let Some(t) = self.retry_after {
            tokio::time::sleep_until(t).await;
        }
    }
    fn success(&mut self) {
        self.failures = 0;
        self.retry_after = None;
    }
}
/// Retry state persists until an authenticated, valid response is received.
pub async fn query(
    addresses: &[Address],
    key: &[u8; 32],
    request: &[u8],
    timeout: Duration,
    attempts: u32,
    backoff: &mut Backoff,
) -> Result<Measurement> {
    ensure!(
        !addresses.is_empty() && attempts > 0,
        "no addresses or attempts"
    );
    let mut last = None;
    for attempt in 0..attempts {
        backoff.wait().await;
        let address = &addresses[attempt as usize % addresses.len()];
        let start = Instant::now();
        match tokio::time::timeout(timeout, exchange(address, key, request)).await {
            Ok(Ok((response, time))) => {
                let round_trip = start.elapsed();
                ensure!(round_trip <= timeout, "maximum measurement delay exceeded");
                backoff.success();
                return Ok(Measurement {
                    time,
                    response,
                    round_trip,
                });
            }
            Ok(Err(error)) => {
                last = Some(error);
                backoff.failure();
            }
            Err(_) => {
                last = Some(anyhow::anyhow!("request timed out"));
                backoff.failure();
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no request attempted")))
        .context("no authenticated time response")
}
async fn exchange(
    address: &Address,
    key: &[u8; 32],
    request: &[u8],
) -> Result<(Vec<u8>, VerifiedTime)> {
    let peer = lookup_host(&address.address)
        .await?
        .next()
        .context("DNS returned no addresses")?;
    match address.protocol.as_str() {
        "udp" => {
            let socket = UdpSocket::bind(if peer.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .await?;
            socket.connect(peer).await?;
            socket.send(request).await?;
            let mut buffer = vec![0; MAX_PACKET + 1];
            loop {
                let n = socket.recv(&mut buffer).await?;
                if let Ok(time) = verify_response(request, &buffer[..n], key) {
                    return Ok((buffer[..n].to_vec(), time));
                }
            }
        }
        "tcp" => {
            let mut stream = TcpStream::connect(peer).await?;
            stream.write_all(request).await?;
            let response = read_frame(&mut stream).await?;
            let time = verify_response(request, &response, key)?;
            stream.shutdown().await?;
            Ok((response, time))
        }
        _ => bail!("unsupported transport"),
    }
}
