# Contributing

Copyright © 2026 Naomi Persephone Amethyst <naomi@amethyst.name>.
Contributions are accepted under AGPL-3.0-only without a copyright assignment.
By contributing, you confirm you can license your changes under these terms.

Describe the concrete problem, resulting behavior, applicable RFC section, and
validation in a pull request. Run formatting, Clippy, Rust tests, and independent
network integration. Protocol/crypto changes need negative cases and an
independent fixture or interoperability check; avoid tests that only compare
the implementation against itself. Keep key material out of commits.

Do not silently introduce compatibility with draft Roughtime versions or accept
additional signature contexts. Discuss trust-policy and clock-changing features
before implementing them. Follow SECURITY.md for private vulnerability reports.
