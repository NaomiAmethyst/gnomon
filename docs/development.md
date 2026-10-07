# Development and releases

Gnomon uses a bounded, borrowing packet decoder, separate cryptographic verification, a bounded single signing worker with Merkle batching, UDP reception, and individually limited TCP sessions. CPU-bound signing runs outside Tokio I/O threads. Private root material is only read by the offline `delegate` command. The server reads an online seed, certificate, and pinned public root; it checks they agree before binding sockets.

## Validation

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --bins
python3 tests/reference.py
# Requires local sudo access to systemd; creates only collected transient units.
python3 tests/systemd.py
```

Rust tests cover codec boundaries, arbitrary input, full-request binding, certificate/signature validation, radius/version checks, all batch sizes 1–32, unused Merkle index bits, safe interval arithmetic, evidence authentication, and key-file permissions. Independent Python/OpenSSL fixtures prevent a shared Rust signer/verifier bug from passing unnoticed. Live integration starts three temporary daemons, checks both transports, fragmented/pipelined TCP, malformed/short requests, Rust client output, chained measurements, exclusive evidence files, saved malfeasance evidence from lying servers, exit on delegation expiry, and SIGTERM shutdown. Test clocks explicitly opt out of synchronization checks; deployment defaults require them.

`python3 tests/reference.py --write-fixture` regenerates deterministic original fixtures. The Appendix B fixture is extracted from the RFC and carries its separate BSD notice; see `NOTICE`. Test seeds are not deployment keys.

For longer fuzzing:

```sh
cargo install cargo-fuzz --locked
rustup toolchain install nightly
cargo +nightly fuzz run packet -- -max_total_time=300
```

Keep fuzz failures as regression cases. Property tests are bounded and run in regular CI; sustained coverage-guided fuzzing is a separate developer activity.

## Packaging

Build **static musl binaries** for the architecture being packaged:

```sh
rustup target add x86_64-unknown-linux-musl
# Install musl-tools and rpm from your distribution's package manager.
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo build --release --locked --target x86_64-unknown-linux-musl
python3 packaging/build-packages.py \
  --binaries target/x86_64-unknown-linux-musl/release --arch amd64
```

Use `--arch arm64` with native aarch64 musl binaries. The packaging script requires Python 3.11+, `dpkg-deb`, and `rpmbuild`; `--format deb`, `rpm`, or `tar` selects one. Debian and RPM configs are preserved on upgrades. The package contains both binaries, configuration, systemd unit, license, and documentation; no private keys. A stopped installation is intentional. The portable tarball mirrors installed paths and is extracted by the operator. Release checksums and dependency manifests are generated in CI. Build artifacts are not reproducible byte-for-byte yet: toolchain/base image/package repository updates and archive timestamps affect bytes.

## CI and releases

PR and main-branch CI runs Rust 1.85 and stable, then native amd64/arm64 musl package builds and an amd64 scratch-container integration test. The security workflow audits RustSec advisories weekly and on changes; Dependabot monitors Cargo, action commits, and base images. GitHub Actions are pinned to immutable commits. Grant default repository workflow tokens read-only; release jobs request narrower write scopes explicitly.

1. Update `Cargo.toml`, lockfile if needed, `docs/release-notes.md`, and version references. Regenerate `THIRD-PARTY-NOTICES` with `python3 packaging/collect-licenses.py` after dependency changes.
2. Run all checks and inspect changes. Obtain independent review of cryptographic/protocol changes.
3. Push a matching `vVERSION` tag. CI verifies the version, builds both architectures, and attests binary artifacts.
4. CI publishes multiarchitecture GHCR images with SBOM/provenance and creates a **draft** GitHub release containing packages, static tarballs, source with vendored Rust dependencies for offline builds, checksums, and dependency manifests.
5. Review the draft and publish it. Make GHCR package visibility public for open-source distribution. Set branch protection to require CI and Dependency audit.

No GitHub repository or registry publishing is performed by the local setup. Tagged builds need standard `GITHUB_TOKEN` permissions for releases, packages, and attestations; no long-lived PAT is needed. Clients can verify package provenance with `gh attestation verify FILE --repo NaomiAmethyst/gnomon`. Hosting a modified AGPL service requires providing its corresponding source according to the license; retain accessible source/release links and license notices.
