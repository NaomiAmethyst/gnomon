//! Roughtime signatures, delegation, Merkle batching, and response verification.
use crate::wire::*;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};

const DELEGATION_CONTEXT: &[u8] = b"Roughtime v1 delegation signature\0";
const RESPONSE_CONTEXT: &[u8] = b"Roughtime v1 response signature\0";
/// SHA-512 over the concatenated parts, truncated to 32 bytes (RFC 10049 §5.3).
pub fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let output = h.finalize();
    let mut result = [0; 32];
    result.copy_from_slice(&output[..32]);
    result
}

/// The SRV value identifying a server by its long-term public key.
pub fn server_id(key: &[u8; 32]) -> [u8; 32] {
    hash(&[&[0xff], key])
}

fn signed_bytes(context: &[u8], value: &[u8]) -> Vec<u8> {
    [context, value].concat()
}

fn verify(key: &[u8], signature: &[u8], context: &[u8], value: &[u8]) -> Result<()> {
    let k = VerifyingKey::from_bytes(&fixed(key)?).map_err(|_| Error::Signature)?;
    if k.is_weak() {
        return Err(Error::Signature);
    }
    let sig = Signature::from_bytes(&fixed(signature)?);
    k.verify_strict(&signed_bytes(context, value), &sig)
        .map_err(|_| Error::Signature)
}

/// Signs a delegation of `online` valid from `mint` to `maxt` inclusive, and
/// returns the encoded CERT message.
pub fn certificate(root: &SigningKey, online: &[u8; 32], mint: u64, maxt: u64) -> Result<Vec<u8>> {
    if mint > maxt {
        return Err(Error::Format("delegation interval"));
    }
    let dele = encode(vec![
        (PUBK, online.to_vec()),
        (MINT, mint.to_le_bytes().to_vec()),
        (MAXT, maxt.to_le_bytes().to_vec()),
    ])?;
    let sig = root.sign(&signed_bytes(DELEGATION_CONTEXT, &dele));
    encode(vec![(DELE, dele), (SIG, sig.to_bytes().to_vec())])
}

/// Verifies a CERT message against the long-term key. Returns the delegated
/// online key and its validity bounds.
pub fn check_certificate(cert: &[u8], root: &[u8; 32]) -> Result<([u8; 32], u64, u64)> {
    let c = Message::decode(cert)?;
    let d = c.required(DELE)?;
    verify(root, c.required(SIG)?, DELEGATION_CONTEXT, d)?;
    let d = Message::decode(d)?;
    let mint = u64_value(d.required(MINT)?)?;
    let maxt = u64_value(d.required(MAXT)?)?;
    if mint > maxt {
        return Err(Error::Format("delegation interval"));
    }
    let key = fixed(d.required(PUBK)?)?;
    let k = VerifyingKey::from_bytes(&key).map_err(|_| Error::Signature)?;
    if k.is_weak() {
        return Err(Error::Signature);
    }
    Ok((key, mint, maxt))
}

/// Builds a 1036-byte version 1 request packet for the server identified by
/// its long-term key.
pub fn request(nonce: &[u8; 32], key: &[u8; 32]) -> Result<Vec<u8>> {
    // 5 tags (40 bytes) + 72 bytes of fields + 912 bytes padding = 1024.
    packet(encode(vec![
        (VER, 1u32.to_le_bytes().to_vec()),
        (NONC, nonce.to_vec()),
        (TYPE, 0u32.to_le_bytes().to_vec()),
        (SRV, server_id(key).to_vec()),
        (ZZZZ, vec![0; 912]),
    ])?)
}

/// Validates a request packet addressed to this server (or to no particular
/// server) and returns its nonce.
pub fn check_request(p: &[u8], key: &[u8; 32]) -> Result<[u8; 32]> {
    let m = unpack(p)?;
    if u32_value(m.required(TYPE)?)? != 0 || !versions(m.required(VER)?)?.contains(&1) {
        return Err(Error::Format("unsupported request"));
    }
    if m.get(SRV).is_some_and(|v| v != server_id(key)) {
        return Err(Error::Format("unknown server identity"));
    }
    if m.get(ZZZZ).is_some_and(|v| v.iter().any(|b| *b != 0)) {
        return Err(Error::Format("nonzero padding"));
    }
    fixed(m.required(NONC)?)
}

/// A bounded tree: maximum 32 leaves, five siblings, fitting 1024-byte requests.
pub fn merkle(requests: &[Vec<u8>]) -> Result<([u8; 32], Vec<Vec<u8>>)> {
    if requests.is_empty() || requests.len() > 32 {
        return Err(Error::Format("batch size"));
    }
    let mut level: Vec<_> = requests.iter().map(|r| hash(&[&[0], r])).collect();
    // Pad the tree with copies of its last leaf. Only real requests get proofs.
    level.resize(level.len().next_power_of_two(), level[level.len() - 1]);
    let mut paths = vec![Vec::new(); requests.len()];
    let mut depth = 0;
    while level.len() > 1 {
        for (i, path) in paths.iter_mut().enumerate() {
            path.extend_from_slice(&level[(i >> depth) ^ 1]);
        }
        level = level
            .chunks_exact(2)
            .map(|p| hash(&[&[1], &p[0], &p[1]]))
            .collect();
        depth += 1;
    }
    Ok((level[0], paths))
}

/// A server's online signing key, its certificate, and the delegation bounds.
pub struct Identity {
    online: SigningKey,
    cert: Vec<u8>,
    pub root: [u8; 32],
    pub mint: u64,
    pub maxt: u64,
}

impl Identity {
    /// Fails unless the certificate is signed by `root` and delegates `online`.
    pub fn new(online: SigningKey, cert: Vec<u8>, root: [u8; 32]) -> Result<Self> {
        let (key, mint, maxt) = check_certificate(&cert, &root)?;
        if online.verifying_key().to_bytes() != key {
            return Err(Error::Format("online key does not match certificate"));
        }
        Ok(Self {
            online,
            cert,
            root,
            mint,
            maxt,
        })
    }

    /// Signs one SREP for a batch of up to 32 requests and returns a response
    /// packet for each, in order.
    pub fn respond(
        &self,
        requests: &[Vec<u8>],
        midpoint: u64,
        radius: u32,
    ) -> Result<Vec<Vec<u8>>> {
        if midpoint < self.mint || midpoint > self.maxt || radius == 0 {
            return Err(Error::Format("time outside delegation or zero radius"));
        }
        let nonces = requests
            .iter()
            .map(|r| check_request(r, &self.root))
            .collect::<Result<Vec<_>>>()?;
        let (root, paths) = merkle(requests)?;
        let srep = encode(vec![
            (VER, 1u32.to_le_bytes().to_vec()),
            (VERS, 1u32.to_le_bytes().to_vec()),
            (MIDP, midpoint.to_le_bytes().to_vec()),
            (RADI, radius.to_le_bytes().to_vec()),
            (ROOT, root.to_vec()),
        ])?;
        let sig = self
            .online
            .sign(&signed_bytes(RESPONSE_CONTEXT, &srep))
            .to_bytes();
        nonces
            .iter()
            .zip(paths)
            .enumerate()
            .map(|(i, (nonce, path))| {
                let mut fields = vec![
                    (NONC, nonce.to_vec()),
                    (TYPE, 1u32.to_le_bytes().to_vec()),
                    (SIG, sig.to_vec()),
                    (SREP, srep.clone()),
                    (CERT, self.cert.clone()),
                    (PATH, path),
                    (INDX, (i as u32).to_le_bytes().to_vec()),
                ];
                // RFC §7: unknown-tag grease in approximately 1/32 responses.
                let mut random = [0u8; 1];
                if rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut random).is_ok()
                    && random[0] & 31 == 0
                {
                    fields.push((tag(b"ZZZX"), vec![0; 4]));
                }
                let p = packet(encode(fields)?)?;
                if p.len() > requests[i].len() {
                    return Err(Error::Format("response amplification"));
                }
                Ok(p)
            })
            .collect()
    }
}

/// An authenticated MIDP/RADI pair in Unix seconds.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifiedTime {
    pub midpoint: u64,
    pub radius: u32,
}

impl VerifiedTime {
    /// Earliest time the server could have signed the response.
    pub fn lower(&self) -> i128 {
        self.midpoint as i128 - self.radius as i128
    }

    /// Latest time the server could have signed the response.
    pub fn upper(&self) -> i128 {
        self.midpoint as i128 + self.radius as i128
    }
}

/// Fully authenticates a response to `request` against the server's long-term
/// key: certificate, signature, signed fields, nonce, and Merkle proof.
pub fn verify_response(
    request: &[u8],
    response: &[u8],
    root_key: &[u8; 32],
) -> Result<VerifiedTime> {
    let nonce = check_request(request, root_key)?;
    let m = unpack(response)?;
    if u32_value(m.required(TYPE)?)? != 1 || m.required(NONC)? != nonce {
        return Err(Error::Proof);
    }
    let (online, mint, maxt) = check_certificate(m.required(CERT)?, root_key)?;
    let srep = m.required(SREP)?;
    verify(&online, m.required(SIG)?, RESPONSE_CONTEXT, srep)?;
    let s = Message::decode(srep)?;
    if u32_value(s.required(VER)?)? != 1 || !versions(s.required(VERS)?)?.contains(&1) {
        return Err(Error::Format("response version"));
    }
    let midpoint = u64_value(s.required(MIDP)?)?;
    let radius = u32_value(s.required(RADI)?)?;
    if radius == 0 || midpoint < mint || midpoint > maxt {
        return Err(Error::Format("response time"));
    }
    let path = m.required(PATH)?;
    if path.len() % 32 != 0 || path.len() > 1024 {
        return Err(Error::Format("Merkle path length"));
    }
    let mut index = u32_value(m.required(INDX)?)?;
    let mut h = hash(&[&[0], request]);
    for sibling in path.chunks_exact(32) {
        h = if index & 1 == 0 {
            hash(&[&[1], &h, sibling])
        } else {
            hash(&[&[1], sibling, &h])
        };
        index >>= 1;
    }
    if index != 0 || fixed::<32>(s.required(ROOT)?)? != h {
        return Err(Error::Proof);
    }
    Ok(VerifiedTime { midpoint, radius })
}
