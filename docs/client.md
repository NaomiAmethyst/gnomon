# Client use and evidence

## Pinned query

```sh
gnomon query --server time.example.org:5319 --public-key BASE64_KEY
gnomon query --server '[2001:db8::1]:5319' --public-key BASE64_KEY --transport tcp
```

The client authenticates the server's long-term public key, delegated signing key, timestamp interval, and inclusion of its exact request. Defaults: three-second maximum measurement delay, four attempts, UDP then TCP fallback. Invalid UDP packets are ignored until a valid response or timeout; they do not reset backoff. `--transport udp` or `tcp` forces a transport.

Output uses Unix seconds. `midpoint`/`radius` describe the server's signed moment of processing, not an exact current time. `earliestAtReceipt` is MIDP−RADI; `latestAtReceipt` adds the measured monotonic RTT rounded up to MIDP+RADI. Time spent after receipt and local oscillator drift require further widening when using these bounds later. Authentication proves the server made a statement; it does not prove that server is honest.

## Multi-server measurement

Use a reviewed [RFC-format list](https://www.rfc-editor.org/rfc/rfc10049.html#section-8.3), for example:

```json
{
  "servers": [
    {
      "name": "Operator A",
      "version": 1,
      "publicKeyType": "ed25519",
      "publicKey": "BASE64_ROOT_PUBLIC_KEY",
      "addresses": [
        {"protocol": "udp", "address": "time.example.org:5319"},
        {"protocol": "tcp", "address": "time.example.org:5319"}
      ]
    }
  ],
  "sources": ["https://trusted.example.org/servers.json"],
  "reports": "https://trusted.example.org/reports"
}
```

Add **at least three identities belonging to independent operators** before measuring. Version is the server's highest supported version. Addresses should list UDP followed by TCP for fallback. IPv6 addresses must be bracketed and must not contain zone identifiers. Base64 uses RFC 4648 standard encoding with padding. List source/report URLs must use HTTPS. Gnomon validates these fields, but does not fetch lists or post reports.

```sh
gnomon measure --servers servers.json --count 3 --evidence measurement.json
gnomon verify-evidence measurement.json
```

The client randomly chooses distinct identities, queries each sequentially, then repeats the same order. Each request after the first binds the entire previous authenticated response and fresh 32-byte randomness. A successful measurement returns receipt-time bounds plus an evidence file. The lower bound is the greatest lower bound from the sequence, and the upper bound is the final response's upper bound plus its RTT. These bounds depend on server correctness; causal consistency is not a majority-vote or correctness proof.

Every earlier/later pair is checked for `MIDP_i − RADI_i <= MIDP_j + RADI_j`. If this fails after authentication, the CLI saves evidence and exits with an error. Signature failures, broken proofs, and network failures never become malfeasance reports. Output files are created exclusively: use a fresh path for each run. Verify saved evidence offline before sending it to a list provider; an inconsistent authenticated chain establishes that at least one participating server made a wrong statement, not which one. The keys inside evidence must also be compared to your independently trusted server list before interpreting a report as an accusation.

The common evidence media type is `application/roughtime-malfeasance+json`. Uploads and list updates are manual so operators can review trust and reporting policies. If an automated uploader is added, it must implement RFC §8.4.2's exponential HTTP retry backoff and only upload authenticated causal inconsistencies. HTTP reporting alone must not authorize key revocation.
