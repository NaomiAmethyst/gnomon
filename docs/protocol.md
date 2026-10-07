# RFC 10049 conformance

The normative specification is [RFC 10049](https://www.rfc-editor.org/rfc/rfc10049.html), an Experimental RFC, version number 1. No draft compatibility mode is implemented.

| RFC sections | Implementation |
|---|---|
| 4, 5 | Little-endian uint32/uint64, numeric tag sorting, duplicate rejection, aligned bounded offsets, exact `ROUGHTIM` packet framing |
| 5.1 | VER/NONC/TYPE required, sorted unique 1–32 versions, 32-byte nonce, optional SRV resolution, zero padding, unknown tags ignored |
| 5.2 | Mandatory response fields, TYPE=1, nested SREP VER=1, Unix seconds, nonzero seconds radius, VERS, offline delegation |
| 5.2.1, 5.2.6 | Ed25519 over the context **including its terminating NUL**, then the exact encoded signed message |
| 5.3 | SHA-512 truncated to the first 32 bytes; leaves hash `0x00 || complete request packet`; internal nodes hash `0x01 || left || right` |
| 5.3.1, 5.4 | Certificate and SREP signatures, inclusive delegation bounds, echoed nonce, root reconstruction, unused INDX bits zero |
| 5, 9.7 | UDP datagrams and persistent framed TCP; responses never exceed their request; bounded batching and silent invalid-request drops |
| 5 | Client exponential retry delay 1, 1.5, 2.25… seconds, capped at 86400; success resets only after a valid authenticated response; single-server auto UDP/TCP fallback |
| 8.2 | Randomly choose at least three distinct pinned identities; identical server order twice; fresh randomness; H(previous full response || rand); check every causally ordered pair |
| 8.3, 8.4.1 | Common server-list JSON input and base64 request/response/randomness evidence JSON; offline chain verification |
| 9.3 | RFC 8032 seed generation/expansion through Ed25519; OS randomness; private-file permissions and zeroization |

## Bounded choices and optional behavior

The server accepts packets up to 4096 bytes and requires a 1024-byte request message even on TCP. Responding to shorter messages is optional in the RFC. It supports one root identity per process and rejects mismatched SRV. Batch size is at most 32, tree height at most five; incomplete final levels are padded by duplicating the final leaf. Maximum generated responses are smaller than 1024 bytes, so the minimum accepted request always covers them. The client can verify up to 32 siblings as specified by the RFC, subject to its packet cap.

UDP DF handling and TCP out-of-order responses are optional and not enabled. TCP handles outstanding requests sequentially. RADI is at least 3 in the daemon, with kernel clock health bounds. Library verification accepts any nonzero RFC radius. The daemon greases about 1/32 responses with an undefined tag (§7); all signed times remain correct. Unknown-field tolerance is covered by tests. Source-list updates and HTTPS malfeasance upload are operator-managed; reports are written locally for review. The CLI fails visibly on malfeasance rather than automatically beginning another measurement; operators can retry with another reviewed server set. These operational choices are explicit so a consumer can evaluate the SHOULD-level recommendations.

Client retries are bounded by `--attempts`; the retained `Backoff` library object preserves state across calls. A newly invoked one-shot CLI starts a new state; repeated invocations must be rate-limited by the operator. All measurements apply a monotonic maximum request/response delay. The library and CLI never change the clock.

## Signature context discrepancy in Appendix B

RFC §§5.2.1 and 5.2.6 specify `Roughtime v1 response signature\0` and `Roughtime v1 delegation signature\0`. The published Appendix B evidence instead verifies with `RoughTime` (capital T). This was independently reproduced using Python cryptography/OpenSSL. Gnomon implements the **normative section spelling**, rejects the Appendix B signatures, and keeps the example as a negative regression fixture. `tests/reference.py` generates separate interoperable fixtures with the normative spelling and validates live Rust daemon responses. No silent alternative-context acceptance is performed. Revisit this choice if the RFC Editor publishes an applicable erratum.

Gnomon has not yet been tested against independent public RFC 10049-v1 services. Cross-implementation testing should explicitly check context spelling, seconds timestamps, full-packet leaf hashing, and version negotiation.
