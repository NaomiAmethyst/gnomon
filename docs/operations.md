# Operating Gnomon

## Clock and trust requirements

Run a disciplined system clock (for example, chrony with authenticated upstreams or a suitable hardware source). Gnomon checks Linux `adjtimex` without changing the clock: `TIME_ERROR`, `STA_UNSYNC`, `STA_CLOCKERR`, or a maximum error beyond the configured radius suspends signing. Startup fails if clock health or delegation validity is wrong. Kernel maximum error rounded up to seconds, plus two seconds for timestamp truncation and leap ambiguity, must fit in `radius_seconds`. The minimum configured radius is 3 seconds. The operator remains responsible for actual UTC accuracy; a kernel status flag cannot prove the upstream clock is honest.

`require_synchronized_clock = false` is an explicit operator override for testing or a separately monitored clock. It emits a warning. Do not disable it just to make a public deployment start. Containers share their host's clock; synchronize the host, and give the container no clock-setting capabilities.

## Generate and delegate keys

Run this on the **offline root machine**:

```sh
gnomon keygen --out root.key > root.pub
```

Run this on the server (or a secure provisioning machine):

```sh
gnomon keygen --out online.key > online.pub
```

Transfer only `online.pub` to the offline machine. Issue a short, deliberate validity interval using Unix seconds; for example, a week beginning at issuance:

```sh
mint=$(date +%s)
maxt=$((mint + 604800))
gnomon delegate --root-key root.key --online-public-key "$(cat online.pub)" \
  --mint "$mint" --maxt "$maxt" --out delegation.cert
```

Transfer the certificate and root **public** key to the server. Keep `root.key` offline. Private seeds are raw 32-byte RFC 8032 seeds; generated files have mode 0600. Loading rejects group/world-readable seeds, symlinks, nonregular files, and wrong lengths. Commands never overwrite existing output files.

## Configuration

Copy `packaging/gnomon.toml.example` to `/etc/gnomon/gnomon.toml`. Set `root_public_key` to `root.pub` and provision `online.key` and `delegation.cert` at the configured paths. All fields are documented in that example; unknown fields cause an error. `listen` is a numeric socket address: `0.0.0.0:5319` for IPv4 or `[::]:5319` for IPv6. IPv4 acceptance on an IPv6 wildcard depends on host dual-stack settings. One identity and listen address are supported per process; run additional instances for multiple identities.

The packet cap is 4096 bytes. Requests with messages shorter than 1024 bytes are silently dropped on both transports. Connections, signing queue capacity, and accepted signing requests per second have explicit bounds. The rate limit is global and enforced in one-second windows before signing; it does not promise per-client fairness or defeat link saturation. Use firewall/source rate limits at the network edge for an exposed server. TCP read, queue, and write operations share a per-request deadline, and each TCP connection can issue multiple requests.

## systemd and packages

Install a release package with `sudo dpkg -i gnomon_VERSION_amd64.deb` or `sudo rpm -Uvh gnomon-VERSION-1.x86_64.rpm`. Installation does not generate keys or enable the service. For a source installation, copy both binaries to `/usr/bin`, the unit to `/usr/lib/systemd/system`, and the example config to `/etc/gnomon`.

```sh
sudo install -d -m 0755 /etc/gnomon
sudo install -m 0600 online.key /etc/gnomon/online.key
sudo install -m 0644 delegation.cert /etc/gnomon/delegation.cert
# Edit /etc/gnomon/gnomon.toml with the pinned root public key.
sudo gnomond --config /etc/gnomon/gnomon.toml --check
sudo systemctl daemon-reload
sudo systemctl enable --now gnomon.service
sudo journalctl -u gnomon.service -f
```

systemd 247+ is required for `LoadCredential`. The dynamic user cannot read the host seed directly: systemd copies it into a private credential directory, and the daemon selects `online.key` from systemd's `CREDENTIALS_DIRECTORY`. `GNOMON_ONLINE_KEY` is an explicit path override for other supervisors. systemd credential copies may be root-owned mode 0440 within a protected `/run/credentials/UNIT` mount; the loader checks that trusted directory and ownership before allowing this specific permission exception. Ordinary seed files still require 0600 or stricter. The config and certificate must be readable by the service. The unit restricts filesystem writes, capabilities, namespace creation, system calls, memory, tasks, and file descriptors. The syscall filter explicitly allows `adjtimex`/`clock_adjtime` for read-only health queries. Empty capabilities prevent clock changes; `ProtectClock` is deliberately omitted because it would also block the required read-only queries.

Ensure TCP and UDP port 5319 are permitted by your firewall. Verify with a pinned query from outside your host. `time-sync.target` ordering does not by itself ensure synchronization; the daemon checks it and systemd retries startup failures.

## Docker / Compose

The scratch image contains only static binaries, documentation, and license. The default UID/GID is 65532. Create a `deployment/` directory with the three configuration files above and ensure the online seed is owned by UID 65532 with mode 0600; config/certificate may be 0644. Directory traversal permission must permit UID 65532. Do not make the private seed world-readable.

```sh
sudo chown 65532:65532 deployment/online.key
chmod 600 deployment/online.key
export GNOMON_ROOT_PUBLIC_KEY="$(cat root.pub)"
docker compose up -d
docker compose logs -f
```

For a direct invocation:

```sh
docker run --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --memory 128m \
  -p 5319:5319/udp -p 5319:5319/tcp \
  --mount type=bind,src="$PWD/deployment",dst=/etc/gnomon,readonly \
  ghcr.io/naomiamethyst/gnomon:v0.1.0
```

Compose's healthcheck makes an authenticated local UDP query and needs `GNOMON_ROOT_PUBLIC_KEY`. A scratch container has no shell; use `--entrypoint /usr/bin/gnomon` to run client/key commands. Run provisioning commands with a writable directory mount and the appropriate UID. Key tools never need network access.

## Rotation and monitoring

Rotate online seeds before certificate expiry, obtaining a new certificate from the same offline root. Provision the new seed/certificate together, then restart; live reload is not implemented. Existing in-memory signing keys are zeroized when dropped. Secure storage disposal and backups remain the operator's responsibility. Root compromise requires distributing a new pinned identity to clients.

JSON logs go to stdout/stderr; configure `RUST_LOG=info` or `warn`. Cumulative `accepted`, `dropped`, and `signed` counters are emitted every 30 seconds. `accepted` counts admitted UDP jobs and TCP connections, while `signed` counts responses, including multiple requests on TCP. Monitor authenticated query success, certificate expiry, the host clock discipline, drop rates, and signing-suspended messages. An expired delegation is never used; requests are dropped and an error is logged at most once every 30 seconds. Restart after replacing expired key material.

SIGINT/SIGTERM stops receiving work, closes sessions, and joins worker tasks. A crashed task terminates the service. Allow the configured systemd/container stop interval for in-progress signing to finish. No client address or nonce is logged.
