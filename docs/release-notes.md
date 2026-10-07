Gnomon provides an RFC 10049 version 1 UDP/TCP Roughtime daemon, pinned client,
offline key-delegation tools, and chained evidence generation/verification.

Assets include amd64/arm64 Debian and RPM packages, static Linux tarballs,
corresponding source, dependency manifests, SHA-256 checksums, and GitHub build
attestations. Scratch images are published to ghcr.io/naomiamethyst/gnomon.

Configure keys and a synchronized clock before enabling the service. Read
docs/operations.md and docs/protocol.md, including the RFC Appendix B signature
context discrepancy. This initial implementation has not received an independent
security audit or public-server interoperability validation.
