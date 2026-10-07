# Initial validation record

Validated locally on Linux amd64 on 2026-10-07:

- Rust 1.85.0 and Rust 1.97.1 builds, Clippy with warnings denied, and formatting.
- Fifteen Rust tests, including bounded property tests and all Merkle batch sizes.
- Independent Python/OpenSSL signatures and six-response causal chains against UDP/TCP daemons and extracted Debian binaries; fragmented/pipelined TCP and invalid-request rejection.
- Static musl release binaries, Debian/RPM/tarball generation, package metadata and contents, and systemd unit verification.
- Complete systemd sandbox and credential loading using collected transient services, with Linux synchronized-clock checks enabled.
- Scratch Docker builds, non-root read-only container network tests, Compose validation, and clock health checks with capabilities dropped.
- RustSec dependency audit: no advisories/warnings for the lockfile at validation time.
- GitHub Actions syntax checked with actionlint; Rust API docs built with warnings denied.
- Corresponding-source staging with vendored Cargo dependencies compiled successfully with `--offline --locked`.

The independent source fixture follows the normative signature-context spelling. The RFC Appendix B fixture is retained as a negative test for its documented spelling discrepancy.

The amd64/arm64 GitHub workflow has been configured, but has not run on GitHub yet. arm64 artifacts, registry publishing, and release attestations require the first hosted CI run. Sustained fuzzing, load testing, public RFC-v1 server interoperability, and an independent security audit remain outstanding. These checks are implementation evidence, not a security certification.
