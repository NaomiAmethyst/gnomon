# Gnomon

Gnomon is a Rust implementation of [RFC 10049 Roughtime version 1](https://www.rfc-editor.org/rfc/rfc10049.html): an authenticated rough-time daemon, client, and verification library. Copyright © 2026 Naomi Persephone Amethyst <naomi@amethyst.name>. Licensed under **AGPL-3.0-only**.

`gnomond` serves UDP and TCP on port 5319. It uses offline root-key delegation, Ed25519 signatures, SHA-512 Merkle batches, bounded queues and connections, rate limiting, and Linux clock health checks. `gnomon` queries pinned identities, performs chained measurements across at least three identities, saves RFC-format evidence, and verifies evidence offline. It prints time estimates as JSON; it does not adjust the system clock.

This is a new implementation. Protocol tests and an independent Python/OpenSSL implementation validate its behavior; an independent security audit and interoperability testing against public RFC-v1 servers remain prerequisites for a security-critical rollout. Older draft/Google Roughtime implementations use different wire formats and are not compatible.

## Build and test

Rust 1.85 or newer is required. Linux is the supported deployment platform.

```sh
cargo build --release --locked
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
# Install Python cryptography using your distribution's package manager first.
python3 tests/reference.py --binaries target/release
```

## First deployment

Follow [the operator guide](docs/operations.md) to generate the long-term key on an offline machine, certify an online key, configure a synchronized clock, and start the daemon. Do not put private keys in Git or container images.

```sh
gnomond --config /etc/gnomon/gnomon.toml --check
gnomond --config /etc/gnomon/gnomon.toml
gnomon query --server time.example.org:5319 --public-key BASE64_ROOT_PUBLIC_KEY
gnomon measure --servers servers.json --evidence measurement.json
gnomon verify-evidence measurement.json
```

Single-server queries authenticate an identity; multi-server measurements detect causal inconsistencies. Choose at least three independent operators, not just three keys belonging to one operator. Pin public keys through a trusted distribution channel.

## Packages and containers

GitHub Actions builds `.deb`, `.rpm`, and static tarballs for Linux amd64/arm64, plus a non-root `scratch` image. PRs run protocol, independent network, package, and container checks. Matching `vVERSION` tags publish images to `ghcr.io/naomiamethyst/gnomon`, generate provenance and checksums, and create a draft GitHub release with binaries and corresponding source.

```sh
docker build -t gnomon .
# Place config, certificate, and online seed in deployment/ first.
GNOMON_ROOT_PUBLIC_KEY=BASE64_ROOT_PUBLIC_KEY docker compose up -d
```

The systemd unit uses a dynamic user and credentials to read a root-owned seed. Container configuration is mounted read-only; see [operations](docs/operations.md) for ownership and clock requirements. Package installation leaves the service stopped until configured.

## Documentation

- [Operations, Docker, systemd, rotation, monitoring](docs/operations.md)
- [Protocol conformance and RFC context discrepancy](docs/protocol.md)
- [Client trust, time bounds, and evidence](docs/client.md)
- [Development, tests, fuzzing, and releases](docs/development.md)
- [Security reporting](SECURITY.md) and [contributing](CONTRIBUTING.md)

Repository: https://github.com/NaomiAmethyst/gnomon
