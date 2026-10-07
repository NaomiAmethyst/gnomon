use crate::{
    crypto::{Identity, check_request},
    keys,
    wire::{MAGIC, MAX_PACKET},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::{
    hash::{BuildHasher, RandomState},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
};

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub online_key: PathBuf,
    pub certificate: PathBuf,
    pub root_public_key: String,
    pub radius_seconds: u32,
    pub require_synchronized_clock: bool,
    pub max_signatures_per_second: u32,
    pub max_requests_per_second_per_source: u32,
    pub max_connections: usize,
    pub queue_capacity: usize,
    pub io_timeout_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 5319)),
            online_key: "/etc/gnomon/online.key".into(),
            certificate: "/etc/gnomon/delegation.cert".into(),
            root_public_key: String::new(),
            radius_seconds: 3,
            require_synchronized_clock: true,
            max_signatures_per_second: 1000,
            max_requests_per_second_per_source: 100,
            max_connections: 128,
            queue_capacity: 256,
            io_timeout_seconds: 5,
        }
    }
}

impl Config {
    pub fn read(path: &Path) -> Result<Self> {
        ensure!(
            std::fs::metadata(path)?.len() <= 65536,
            "config file too large"
        );
        let c: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        ensure!(
            c.radius_seconds >= 3,
            "radius must be at least 3 seconds without a leap-second source"
        );
        ensure!(
            (1..=1_000_000).contains(&c.max_signatures_per_second)
                && (1..=1_000_000).contains(&c.max_requests_per_second_per_source),
            "rate limits out of range"
        );
        ensure!(
            (1..=65536).contains(&c.queue_capacity) && (1..=65536).contains(&c.max_connections),
            "resource limits out of range"
        );
        ensure!(
            (1..=300).contains(&c.io_timeout_seconds),
            "I/O timeout out of range"
        );
        Ok(c)
    }

    pub fn identity(&self) -> Result<Identity> {
        let root = crate::wire::fixed(
            &STANDARD
                .decode(&self.root_public_key)
                .context("decode root_public_key")?,
        )?;
        let online = if let Some(path) = std::env::var_os("GNOMON_ONLINE_KEY") {
            keys::load(&PathBuf::from(path))?
        } else if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
            keys::load_credential(&PathBuf::from(dir).join("online.key"))?
        } else {
            keys::load(&self.online_key)?
        };
        ensure!(
            std::fs::metadata(&self.certificate)?.len() <= crate::wire::MAX_PACKET as u64,
            "certificate too large"
        );
        Ok(Identity::new(
            online,
            std::fs::read(&self.certificate)?,
            root,
        )?)
    }
}

pub fn unix_time() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// Linux's NTP discipline must be healthy and fit inside the advertised radius.
pub fn check_clock(c: &Config) -> Result<()> {
    if !c.require_synchronized_clock {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        // SAFETY: timex is a C POD structure. modes=0 requests a read-only query.
        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        // SAFETY: pointer is valid, exclusive, and correctly aligned for the syscall.
        let state = unsafe { libc::adjtimex(&mut tx) };
        ensure!(
            state >= 0,
            "adjtimex failed: {}",
            std::io::Error::last_os_error()
        );
        ensure!(
            state != libc::TIME_ERROR && tx.status & (libc::STA_UNSYNC | libc::STA_CLOCKERR) == 0,
            "kernel clock is unsynchronized"
        );
        ensure!(
            tx.maxerror >= 0
                && (tx.maxerror as u64).div_ceil(1_000_000) + 2 <= c.radius_seconds as u64,
            "kernel maximum clock error exceeds configured radius"
        );
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!(
            "clock health checks require Linux; explicitly disable for a trusted external clock"
        )
    }
}

pub async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 12];
    stream.read_exact(&mut header).await?;
    ensure!(&header[..8] == MAGIC, "TCP framing magic mismatch");
    let size = crate::wire::u32_value(&header[8..])? as usize;
    ensure!(
        (8..=MAX_PACKET - 12).contains(&size),
        "TCP frame length out of range"
    );
    let mut packet = vec![0; 12 + size];
    packet[..12].copy_from_slice(&header);
    stream.read_exact(&mut packet[12..]).await?;
    Ok(packet)
}

/// Smallest accepted request: a 1024-byte message plus 12 bytes of framing.
const MIN_REQUEST: usize = 1036;
/// Per-source windows are hashed into a fixed table so memory stays bounded.
const SOURCE_BUCKETS: usize = 4096;
const ERROR_LOG_INTERVAL: Duration = Duration::from_secs(30);
const ACCEPT_RETRY: Duration = Duration::from_millis(100);
const EXPIRY_WARNING_SECONDS: u64 = 86400;

struct Job {
    request: Vec<u8>,
    reply: oneshot::Sender<Vec<u8>>,
}

#[derive(Default)]
struct Counters {
    accepted: AtomicU64,
    dropped: AtomicU64,
    signed: AtomicU64,
}

/// A one-second fixed window.
#[derive(Clone)]
struct Window {
    start: Instant,
    used: u32,
    max: u32,
}

impl Window {
    fn new(max: u32) -> Self {
        Self {
            start: Instant::now(),
            used: 0,
            max,
        }
    }

    /// Consumes one unit, or returns how long until the next window opens.
    fn try_acquire(&mut self) -> std::result::Result<(), Duration> {
        let elapsed = self.start.elapsed();
        if elapsed >= Duration::from_secs(1) {
            self.start = Instant::now();
            self.used = 0;
        }
        if self.used >= self.max {
            return Err(Duration::from_secs(1).saturating_sub(elapsed));
        }
        self.used += 1;
        Ok(())
    }
}

/// Request windows keyed by IPv4 address or IPv6 /64. Sources that hash
/// together share a window; the hash key is random per process.
struct SourceLimiter {
    hasher: RandomState,
    windows: Vec<Window>,
}

impl SourceLimiter {
    fn new(max: u32) -> Self {
        Self {
            hasher: RandomState::new(),
            windows: vec![Window::new(max); SOURCE_BUCKETS],
        }
    }

    fn allow(&mut self, source: IpAddr) -> bool {
        let source = match source.to_canonical() {
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
            v4 => v4,
        };
        let index = self.hasher.hash_one(source) as usize % self.windows.len();
        self.windows[index].try_acquire().is_ok()
    }
}

/// Rate-limits a repeating log message.
struct Throttle(Option<Instant>);

impl Throttle {
    fn ready(&mut self) -> bool {
        if self.0.is_some_and(|t| t.elapsed() < ERROR_LOG_INTERVAL) {
            return false;
        }
        self.0 = Some(Instant::now());
        true
    }
}

struct Shared {
    config: Config,
    identity: Identity,
    counters: Counters,
    sources: Mutex<SourceLimiter>,
    sender: mpsc::Sender<Job>,
}

impl Shared {
    fn drop_requests(&self, n: usize) {
        self.counters.dropped.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Validates a request and queues it for signing.
    fn submit(&self, request: &[u8], source: IpAddr) -> Option<oneshot::Receiver<Vec<u8>>> {
        let admitted = request.len() >= MIN_REQUEST
            && check_request(request, &self.identity.root).is_ok()
            && self
                .sources
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .allow(source);
        let (reply, rx) = oneshot::channel();
        let job = Job {
            request: request.to_vec(),
            reply,
        };
        if !admitted || self.sender.try_send(job).is_err() {
            self.drop_requests(1);
            return None;
        }
        self.counters.accepted.fetch_add(1, Ordering::Relaxed);
        Some(rx)
    }

    fn log_status(&self) {
        let expires_in = unix_time()
            .map(|now| self.identity.maxt.saturating_sub(now))
            .unwrap_or(0);
        tracing::info!(
            accepted = self.counters.accepted.load(Ordering::Relaxed),
            dropped = self.counters.dropped.load(Ordering::Relaxed),
            signed = self.counters.signed.load(Ordering::Relaxed),
            delegation_expires_in_seconds = expires_in,
            "server counters"
        );
        if expires_in < EXPIRY_WARNING_SECONDS {
            tracing::warn!(
                maxt = self.identity.maxt,
                "delegation expires within a day; provision a new online key and certificate"
            );
        }
    }
}

/// Batches queued requests and signs them. Signing is paced rather than
/// dropping requests, so under load each signature covers more requests.
/// An expired delegation is permanent, so it stops the daemon.
async fn sign(
    shared: Arc<Shared>,
    mut receiver: mpsc::Receiver<Job>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let mut signatures = Window::new(shared.config.max_signatures_per_second);
    let mut errors = Throttle(None);
    loop {
        let first = tokio::select! {
            _ = stop.changed() => return Ok(()),
            job = receiver.recv() => match job {
                Some(job) => job,
                None => return Ok(()),
            },
        };
        while let Err(wait) = signatures.try_acquire() {
            tokio::select! {
                _ = stop.changed() => return Ok(()),
                _ = tokio::time::sleep(wait) => {}
            }
        }
        let mut batch = vec![first];
        while batch.len() < 32 {
            match receiver.try_recv() {
                Ok(job) => batch.push(job),
                Err(_) => break,
            }
        }
        let now = unix_time()?;
        ensure!(
            now <= shared.identity.maxt,
            "delegation expired at {}; provision a new online key and certificate",
            shared.identity.maxt
        );
        if let Err(error) = check_clock(&shared.config) {
            if errors.ready() {
                tracing::error!(%error, "signing suspended");
            }
            shared.drop_requests(batch.len());
            continue;
        }
        let (requests, replies): (Vec<_>, Vec<_>) =
            batch.into_iter().map(|j| (j.request, j.reply)).unzip();
        let signer = shared.clone();
        let signed = tokio::task::spawn_blocking(move || {
            signer
                .identity
                .respond(&requests, now, signer.config.radius_seconds)
        })
        .await?;
        match signed {
            Ok(responses) => {
                shared
                    .counters
                    .signed
                    .fetch_add(responses.len() as u64, Ordering::Relaxed);
                for (reply, response) in replies.into_iter().zip(responses) {
                    let _ = reply.send(response);
                }
            }
            Err(error) => {
                if errors.ready() {
                    tracing::error!(%error, "signing failed; check delegation and clock");
                }
                shared.drop_requests(replies.len());
            }
        }
    }
}

async fn serve_udp(
    socket: UdpSocket,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let socket = Arc::new(socket);
    let permits = Arc::new(Semaphore::new(shared.config.queue_capacity));
    let mut replies = JoinSet::new();
    let mut errors = Throttle(None);
    let mut buffer = vec![0; MAX_PACKET + 1];
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            Some(result) = replies.join_next() => result?,
            received = socket.recv_from(&mut buffer) => {
                let (n, peer) = match received {
                    Ok(received) => received,
                    Err(error) => {
                        if errors.ready() {
                            tracing::warn!(%error, "UDP receive failed");
                        }
                        continue;
                    }
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    shared.drop_requests(1);
                    continue;
                };
                let Some(rx) = shared.submit(&buffer[..n], peer.ip()) else {
                    continue;
                };
                let socket = socket.clone();
                let mut stop = stop.clone();
                replies.spawn(async move {
                    let _permit = permit;
                    tokio::select! {
                        _ = stop.changed() => {}
                        result = rx => {
                            if let Ok(response) = result {
                                let _ = socket.send_to(&response, peer).await;
                            }
                        }
                    }
                });
            }
        }
    }
    while replies.join_next().await.is_some() {}
    Ok(())
}

async fn serve_tcp(
    listener: TcpListener,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(shared.config.max_connections));
    let mut sessions = JoinSet::new();
    let mut errors = Throttle(None);
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            Some(result) = sessions.join_next() => result?,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        shared.drop_requests(1);
                        continue;
                    };
                    let session = tcp_session(stream, peer.ip(), shared.clone(), stop.clone());
                    sessions.spawn(async move {
                        let _permit = permit;
                        session.await;
                    });
                }
                // Usually EMFILE, ENFILE, or ECONNABORTED. All are transient;
                // pause briefly so descriptor exhaustion does not spin.
                Err(error) => {
                    if errors.ready() {
                        tracing::warn!(%error, "TCP accept failed");
                    }
                    tokio::select! {
                        _ = stop.changed() => break,
                        _ = tokio::time::sleep(ACCEPT_RETRY) => {}
                    }
                }
            },
        }
    }
    while sessions.join_next().await.is_some() {}
    Ok(())
}

async fn tcp_session(
    mut stream: TcpStream,
    source: IpAddr,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let deadline = Duration::from_secs(shared.config.io_timeout_seconds);
    loop {
        let served = tokio::select! {
            _ = stop.changed() => return,
            result = tokio::time::timeout(deadline, tcp_exchange(&mut stream, source, &shared)) => {
                matches!(result, Ok(Ok(())))
            }
        };
        if !served {
            return;
        }
    }
}

async fn tcp_exchange(stream: &mut TcpStream, source: IpAddr, shared: &Shared) -> Result<()> {
    let request = read_frame(stream).await?;
    let rx = shared
        .submit(&request, source)
        .context("request rejected")?;
    stream.write_all(&rx.await?).await?;
    Ok(())
}

pub async fn run(config: Config) -> Result<()> {
    let identity = config.identity()?;
    check_clock(&config).context("refusing to start with unhealthy clock")?;
    let now = unix_time()?;
    ensure!(
        now >= identity.mint && now <= identity.maxt,
        "delegation is not currently valid"
    );
    if !config.require_synchronized_clock {
        tracing::warn!("clock health checks disabled: operator guarantees radius");
    }
    let udp = UdpSocket::bind(config.listen).await.context("bind UDP")?;
    let tcp = TcpListener::bind(config.listen).await.context("bind TCP")?;
    let (sender, receiver) = mpsc::channel(config.queue_capacity);
    let (stop_tx, stop_rx) = watch::channel(false);
    let listen = config.listen;
    let shared = Arc::new(Shared {
        sources: Mutex::new(SourceLimiter::new(
            config.max_requests_per_second_per_source,
        )),
        config,
        identity,
        counters: Counters::default(),
        sender,
    });
    let mut tasks = JoinSet::new();
    tasks.spawn(sign(shared.clone(), receiver, stop_rx.clone()));
    tasks.spawn(serve_udp(udp, shared.clone(), stop_rx.clone()));
    tasks.spawn(serve_tcp(tcp, shared.clone(), stop_rx));
    let mut status = tokio::time::interval(Duration::from_secs(30));
    let mut shutdown = std::pin::pin!(shutdown_signal());
    tracing::info!(%listen, maxt = shared.identity.maxt, "Roughtime UDP/TCP ready");
    let result = loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown requested");
                break Ok(());
            }
            _ = status.tick() => shared.log_status(),
            Some(result) = tasks.join_next() => {
                let error = match result {
                    Ok(Ok(())) => anyhow::anyhow!("server task exited unexpectedly"),
                    Ok(Err(error)) => error,
                    Err(error) => error.into(),
                };
                tracing::error!(error = format!("{error:#}"), "stopping");
                break Err(error);
            }
        }
    };
    let _ = stop_tx.send(true);
    while tasks.join_next().await.is_some() {}
    result
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {_ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {}}
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn window_reports_wait_when_exhausted() {
        let mut w = Window::new(2);
        assert!(w.try_acquire().is_ok());
        assert!(w.try_acquire().is_ok());
        let wait = w.try_acquire().unwrap_err();
        assert!(wait > Duration::ZERO && wait <= Duration::from_secs(1));
        w.start -= Duration::from_secs(1);
        assert!(w.try_acquire().is_ok());
    }

    #[test]
    fn sources_are_keyed_by_ipv4_address_and_ipv6_prefix() {
        let mut limiter = SourceLimiter::new(1);
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let same_64: IpAddr = "2001:db8::ffff:1".parse().unwrap();
        assert!(limiter.allow(a));
        assert!(!limiter.allow(same_64));
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        let mut limiter = SourceLimiter::new(1);
        assert!(limiter.allow(v4));
        assert!(!limiter.allow(mapped));
    }
}
