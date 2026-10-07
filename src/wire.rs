//! Bounded, zero-copy decoding. Unknown tags are retained and ignored by callers.
use std::collections::BTreeMap;
use thiserror::Error;

/// Largest packet accepted or produced, including the 12-byte framing.
pub const MAX_PACKET: usize = 4096;
/// Packet framing prefix (RFC 10049 §5).
pub const MAGIC: &[u8; 8] = b"ROUGHTIM";
/// Converts a four-byte ASCII tag to its little-endian numeric value.
pub const fn tag(bytes: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*bytes)
}

pub const VER: u32 = tag(b"VER\0");
pub const SRV: u32 = tag(b"SRV\0");
pub const SIG: u32 = tag(b"SIG\0");
pub const NONC: u32 = tag(b"NONC");
pub const TYPE: u32 = tag(b"TYPE");
pub const PATH: u32 = tag(b"PATH");
pub const SREP: u32 = tag(b"SREP");
pub const CERT: u32 = tag(b"CERT");
pub const INDX: u32 = tag(b"INDX");
pub const RADI: u32 = tag(b"RADI");
pub const MIDP: u32 = tag(b"MIDP");
pub const VERS: u32 = tag(b"VERS");
pub const ROOT: u32 = tag(b"ROOT");
pub const DELE: u32 = tag(b"DELE");
pub const PUBK: u32 = tag(b"PUBK");
pub const MINT: u32 = tag(b"MINT");
pub const MAXT: u32 = tag(b"MAXT");
pub const ZZZZ: u32 = tag(b"ZZZZ");

#[derive(Debug, Error)]
pub enum Error {
    #[error("malformed Roughtime message: {0}")]
    Format(&'static str),
    #[error("signature verification failed")]
    Signature,
    #[error("response does not authenticate this request")]
    Proof,
}

/// Result type for codec and verification errors.
pub type Result<T> = std::result::Result<T, Error>;
/// Decodes an exactly four-byte little-endian value.
pub fn u32_value(b: &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.try_into().map_err(|_| Error::Format("uint32 length"))?,
    ))
}

/// Decodes an exactly eight-byte little-endian value.
pub fn u64_value(b: &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.try_into().map_err(|_| Error::Format("uint64 length"))?,
    ))
}

/// Copies a slice into an array, failing unless its length is exactly `N`.
pub fn fixed<const N: usize>(b: &[u8]) -> Result<[u8; N]> {
    b.try_into()
        .map_err(|_| Error::Format("fixed field length"))
}

/// A decoded message: tag values borrowed from the input buffer.
#[derive(Debug)]
pub struct Message<'a>(BTreeMap<u32, &'a [u8]>);
impl<'a> Message<'a> {
    /// Decodes a message (without packet framing), validating the tag count,
    /// tag order, and offsets (RFC 10049 §4).
    pub fn decode(data: &'a [u8]) -> Result<Self> {
        if data.len() < 8 || data.len() > MAX_PACKET {
            return Err(Error::Format("message length"));
        }
        let n = u32_value(&data[..4])? as usize;
        if n == 0 || n > data.len() / 8 {
            return Err(Error::Format("tag count"));
        }
        let values = &data[8 * n..];
        let mut fields = BTreeMap::new();
        let mut start = 0;
        let mut last_tag = None;
        for i in 0..n {
            let t = u32_value(&data[4 * n + 4 * i..4 * n + 4 * i + 4])?;
            if last_tag.is_some_and(|p| p >= t) {
                return Err(Error::Format("unordered or duplicate tags"));
            }
            let end = if i + 1 == n {
                values.len()
            } else {
                u32_value(&data[4 + 4 * i..8 + 4 * i])? as usize
            };
            if end < start || end > values.len() || (i + 1 < n && end % 4 != 0) {
                return Err(Error::Format("offset"));
            }
            fields.insert(t, &values[start..end]);
            start = end;
            last_tag = Some(t);
        }
        Ok(Self(fields))
    }

    /// Returns a tag's value, if present.
    pub fn get(&self, tag: u32) -> Option<&'a [u8]> {
        self.0.get(&tag).copied()
    }

    /// Returns a tag's value, failing if it is absent.
    pub fn required(&self, tag: u32) -> Result<&'a [u8]> {
        self.get(tag).ok_or(Error::Format("missing mandatory tag"))
    }
}

/// Encodes fields as a message, sorting them by tag. Every value except the
/// last must be a multiple of four bytes long.
pub fn encode(mut fields: Vec<(u32, Vec<u8>)>) -> Result<Vec<u8>> {
    fields.sort_unstable_by_key(|f| f.0);
    if fields.is_empty() || fields.windows(2).any(|p| p[0].0 == p[1].0) {
        return Err(Error::Format("empty or duplicate fields"));
    }
    let size = fields.len() * 8 + fields.iter().map(|f| f.1.len()).sum::<usize>();
    if size > MAX_PACKET {
        return Err(Error::Format("message too large"));
    }
    let mut result = Vec::with_capacity(size);
    result.extend_from_slice(&(fields.len() as u32).to_le_bytes());
    let mut offset = 0;
    for (_, value) in fields.iter().take(fields.len() - 1) {
        offset += value.len();
        if offset % 4 != 0 {
            return Err(Error::Format("unaligned value"));
        }
        result.extend_from_slice(&(offset as u32).to_le_bytes());
    }
    for (t, _) in &fields {
        result.extend_from_slice(&t.to_le_bytes());
    }
    for (_, value) in fields {
        result.extend_from_slice(&value);
    }
    Ok(result)
}

/// Adds `ROUGHTIM` packet framing to an encoded message.
pub fn packet(message: Vec<u8>) -> Result<Vec<u8>> {
    if message.len() + 12 > MAX_PACKET {
        return Err(Error::Format("packet too large"));
    }
    let mut p = MAGIC.to_vec();
    p.extend_from_slice(&(message.len() as u32).to_le_bytes());
    p.extend(message);
    Ok(p)
}

/// Checks packet framing and decodes the enclosed message.
pub fn unpack(p: &[u8]) -> Result<Message<'_>> {
    if p.len() < 12
        || p.len() > MAX_PACKET
        || &p[..8] != MAGIC
        || u32_value(&p[8..12])? as usize != p.len() - 12
    {
        return Err(Error::Format("packet framing"));
    }
    Message::decode(&p[12..])
}

/// Decodes a VER/VERS list: 1–32 strictly ascending uint32 versions.
pub fn versions(data: &[u8]) -> Result<Vec<u32>> {
    if data.is_empty() || data.len() > 128 || data.len() % 4 != 0 {
        return Err(Error::Format("version list length"));
    }
    let v = data
        .chunks_exact(4)
        .map(u32_value)
        .collect::<Result<Vec<_>>>()?;
    if v.windows(2).any(|p| p[0] >= p[1]) {
        return Err(Error::Format("version list order"));
    }
    Ok(v)
}
