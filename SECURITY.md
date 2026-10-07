# Security policy

Report suspected vulnerabilities privately to Naomi Persephone Amethyst at
naomi@amethyst.name. Include the affected revision, reproduction steps, and
impact. Avoid sharing live private keys or sending attack traffic to public time
servers. Please coordinate disclosure before filing a public issue.

Only the latest released version receives fixes during initial development.
This is new cryptographic network software and has not received an independent
security audit. RFC 10049 is Experimental. The daemon authenticates its time
statements; the operator must maintain an accurate clock, protect delegated keys,
and supply source as required by AGPLv3. Clients need independently trusted,
independently operated servers.

Security-sensitive areas include full-packet request binding, context strings,
strict Ed25519 verification, Merkle index/path validation, clock radius,
delegation bounds, entropy, private-file handling, evidence chaining, and
bounded resource use. A signature error is a protocol failure, not proof of
malfeasance. See docs/protocol.md for the known RFC Appendix B discrepancy.
