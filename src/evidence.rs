//! RFC 10049 §8.4.1 evidence; verification never trusts a claimed timestamp.
use crate::{
    crypto::{VerifiedTime, hash, verify_response},
    wire::{NONC, unpack},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rand: Option<String>,
    pub public_key: String,
    pub request: String,
    pub response: String,
}
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Evidence {
    pub responses: Vec<Entry>,
}
impl Evidence {
    pub fn push(
        &mut self,
        rand: Option<&[u8; 32]>,
        public_key: &[u8; 32],
        request: &[u8],
        response: &[u8],
    ) {
        self.responses.push(Entry {
            rand: rand.map(|r| STANDARD.encode(r)),
            public_key: STANDARD.encode(public_key),
            request: STANDARD.encode(request),
            response: STANDARD.encode(response),
        });
    }
    pub fn verify(&self) -> Result<Vec<VerifiedTime>> {
        ensure!(
            !self.responses.is_empty() && self.responses.len() <= 2048,
            "evidence sequence size out of range"
        );
        let mut previous: Option<Vec<u8>> = None;
        let mut times = Vec::new();
        for e in &self.responses {
            ensure!(
                e.request.len() <= 5500 && e.response.len() <= 5500,
                "oversized evidence packet"
            );
            let request = STANDARD.decode(&e.request)?;
            let response = STANDARD.decode(&e.response)?;
            let key = crate::client::decode_key(&e.public_key)?;
            if let Some(prev) = previous {
                let rand = crate::wire::fixed::<32>(
                    &STANDARD.decode(
                        e.rand
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("missing chain randomness"))?,
                    )?,
                )?;
                ensure!(
                    unpack(&request)?.required(NONC)? == hash(&[&prev, &rand]),
                    "broken evidence chain"
                );
            } else if let Some(r) = &e.rand {
                crate::wire::fixed::<32>(&STANDARD.decode(r)?)?;
            }
            times.push(verify_response(&request, &response, &key)?);
            previous = Some(response);
        }
        Ok(times)
    }
}
pub fn inconsistency(times: &[VerifiedTime]) -> Option<(usize, usize)> {
    for (j, later) in times.iter().enumerate() {
        for (i, earlier) in times[..j].iter().enumerate() {
            if earlier.lower() > later.upper() {
                return Some((i, j));
            }
        }
    }
    None
}
