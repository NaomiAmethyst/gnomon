use crate::{
    crypto::{Identity, check_request},
    keys,
    wire::{MAGIC, MAX_PACKET},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
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
    pub max_requests_per_second: u32,
    pub max_connections: usize,
    pub queue_capacity: usize,
    pub io_timeout_seconds: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:5319".parse().unwrap_or_else(|_| unreachable!()),
            online_key: "/etc/gnomon/online.key".into(),
            certificate: "/etc/gnomon/delegation.cert".into(),
            root_public_key: String::new(),
            radius_seconds: 3,
            require_synchronized_clock: true,
            max_requests_per_second: 1000,
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
            c.max_requests_per_second > 0 && c.max_requests_per_second <= 1_000_000,
            "request rate out of range"
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
struct Rate {
    start: Instant,
    used: u32,
    max: u32,
}
impl Rate {
    fn allow(&mut self) -> bool {
        if self.start.elapsed() >= Duration::from_secs(1) {
            self.start = Instant::now();
            self.used = 0;
        }
        if self.used >= self.max {
            false
        } else {
            self.used += 1;
            true
        }
    }
}
async fn tcp_session(
    mut stream: TcpStream,
    sender: mpsc::Sender<Job>,
    root: [u8; 32],
    duration: Duration,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let result: Result<()> = tokio::select! {
            _ = stop.changed() => return,
            result = tokio::time::timeout(duration, async {
                let request = read_frame(&mut stream).await?;
                ensure!(request.len() >= 1036, "short request");
                check_request(&request, &root)?;
                let (reply, rx) = oneshot::channel();
                sender.try_send(Job {request, reply}).context("signing queue full")?;
                let response = rx.await?;
                stream.write_all(&response).await?;
                Ok(())
            }) => result.unwrap_or_else(|_| Err(anyhow::anyhow!("TCP timeout"))),
        };
        if result.is_err() {
            return;
        }
    }
}
pub async fn run(c: Config) -> Result<()> {
    let identity = Arc::new(c.identity()?);
    check_clock(&c).context("refusing to start with unhealthy clock")?;
    let now = unix_time()?;
    ensure!(
        now >= identity.mint && now <= identity.maxt,
        "delegation is not currently valid"
    );
    if !c.require_synchronized_clock {
        tracing::warn!("clock health checks disabled: operator guarantees radius");
    }
    let udp = Arc::new(UdpSocket::bind(c.listen).await.context("bind UDP")?);
    let tcp = TcpListener::bind(c.listen).await.context("bind TCP")?;
    let (sender, mut receiver) = mpsc::channel::<Job>(c.queue_capacity);
    let (stop_tx, stop_rx) = watch::channel(false);
    let counters = Arc::new(Counters::default());
    let mut jobs = JoinSet::new();
    let worker_identity = identity.clone();
    let worker_counters = counters.clone();
    let mut worker_stop = stop_rx.clone();
    let c = Arc::new(c);
    let worker_config = c.clone();
    jobs.spawn(async move {
        let mut rate = Rate {start: Instant::now(), used: 0, max: worker_config.max_requests_per_second};
        let mut health_log = Instant::now()-Duration::from_secs(60);
        loop {
            let first = tokio::select! {_ = worker_stop.changed() => break, j = receiver.recv() => match j {Some(j) => j, None => break}};
            let mut batch = vec![first];
            while batch.len() < 32 {match receiver.try_recv() {Ok(j) => batch.push(j), Err(_) => break}}
            batch.retain(|_| {
                if rate.allow() {true} else {worker_counters.dropped.fetch_add(1, Ordering::Relaxed); false}
            });
            if batch.is_empty() {continue;}
            if let Err(error) = check_clock(&worker_config) {
                if health_log.elapsed() > Duration::from_secs(30) {tracing::error!(%error, "signing suspended"); health_log = Instant::now();}
                worker_counters.dropped.fetch_add(batch.len() as u64, Ordering::Relaxed);
                continue;
            }
            let id = worker_identity.clone();
            let requests: Vec<_> = batch.iter().map(|j| j.request.clone()).collect();
            let radius = worker_config.radius_seconds;
            let signed = tokio::task::spawn_blocking(move || -> Result<_> { Ok(id.respond(&requests, unix_time()?, radius)?) }).await;
            match signed {
                Ok(Ok(responses)) => {
                    worker_counters.signed.fetch_add(responses.len() as u64, Ordering::Relaxed);
                    for (j, response) in batch.into_iter().zip(responses) {let _ = j.reply.send(response);}
                }
                result => {
                    if health_log.elapsed() > Duration::from_secs(30) {tracing::error!(?result, "signing failed; check delegation and clock"); health_log = Instant::now();}
                }
            }
        }
    });
    let permits = Arc::new(Semaphore::new(c.max_connections));
    let udp_permits = Arc::new(Semaphore::new(c.queue_capacity));
    let mut buffer = vec![0; MAX_PACKET + 1];
    let mut metrics = tokio::time::interval(Duration::from_secs(30));
    let mut shutdown = std::pin::pin!(shutdown_signal());
    let mut task_error = None;
    tracing::info!(listen=%c.listen, "Roughtime UDP/TCP ready");
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = metrics.tick() => tracing::info!(accepted=counters.accepted.load(Ordering::Relaxed), dropped=counters.dropped.load(Ordering::Relaxed), signed=counters.signed.load(Ordering::Relaxed), "server counters"),
            Some(result) = jobs.join_next() => { if let Err(error) = result {tracing::error!(%error, "worker task failed"); task_error = Some(error); break;} },
            received = udp.recv_from(&mut buffer) => {
                let (n, peer) = received?;
                if n < 1036 || check_request(&buffer[..n], &identity.root).is_err() {
                    counters.dropped.fetch_add(1, Ordering::Relaxed); continue;
                }
                let Ok(permit) = udp_permits.clone().try_acquire_owned() else {counters.dropped.fetch_add(1, Ordering::Relaxed); continue;};
                let (reply, rx) = oneshot::channel();
                if sender.try_send(Job {request: buffer[..n].to_vec(), reply}).is_err() {counters.dropped.fetch_add(1, Ordering::Relaxed); continue;}
                counters.accepted.fetch_add(1, Ordering::Relaxed);
                let socket = udp.clone();
                let mut stop = stop_rx.clone();
                jobs.spawn(async move {
                    let _permit = permit;
                    tokio::select! {_ = stop.changed() => {}, result = rx => {if let Ok(response) = result {let _ = socket.send_to(&response, peer).await;}}}
                });
            },
            accepted = tcp.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {counters.dropped.fetch_add(1, Ordering::Relaxed); continue;};
                counters.accepted.fetch_add(1, Ordering::Relaxed);
                let tx = sender.clone(); let root = identity.root; let duration = Duration::from_secs(c.io_timeout_seconds); let stop = stop_rx.clone();
                jobs.spawn(async move {let _permit = permit; tcp_session(stream, tx, root, duration, stop).await;});
            },
        }
    }
    tracing::info!("shutdown requested");
    let _ = stop_tx.send(true);
    drop(sender);
    while jobs.join_next().await.is_some() {}
    if let Some(error) = task_error {
        return Err(error.into());
    }
    Ok(())
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
