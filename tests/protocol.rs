#![allow(clippy::unwrap_used, clippy::expect_used)]
use ed25519_dalek::{Signer, SigningKey};
use gnomon::{
    crypto::*,
    evidence::{Evidence, inconsistency},
    wire::*,
};
use proptest::prelude::*;

fn identity() -> Identity {
    let root = SigningKey::from_bytes(&[17; 32]);
    let online = SigningKey::from_bytes(&[29; 32]);
    let cert = certificate(&root, &online.verifying_key().to_bytes(), 100, 2000).unwrap();
    Identity::new(online, cert, root.verifying_key().to_bytes()).unwrap()
}
fn replace_message(message: &[u8], t: u32, value: Vec<u8>) -> Vec<u8> {
    let n = u32_value(&message[..4]).unwrap() as usize;
    let parsed = Message::decode(message).unwrap();
    let mut fields = Vec::new();
    for i in 0..n {
        let tag = u32_value(&message[4 * n + 4 * i..4 * n + 4 * i + 4]).unwrap();
        fields.push((
            tag,
            if tag == t {
                value.clone()
            } else {
                parsed.required(tag).unwrap().to_vec()
            },
        ));
    }
    encode(fields).unwrap()
}
fn replace_packet(p: &[u8], t: u32, v: Vec<u8>) -> Vec<u8> {
    packet(replace_message(&p[12..], t, v)).unwrap()
}

#[test]
fn rfc_appendix_b_uses_nonnormative_context_spelling() {
    // Appendix B signs "RoughTime"; §§5.2.1/5.2.6 require "Roughtime".
    // Keep this test until a published erratum resolves the discrepancy.
    let report: Evidence =
        serde_json::from_str(include_str!("fixtures/rfc10049-appendix-b.json")).unwrap();
    assert!(report.verify().is_err());
}
#[test]
fn independent_openssl_fixture_proves_authenticated_malfeasance() {
    let report: Evidence =
        serde_json::from_str(include_str!("fixtures/reference-v1.json")).unwrap();
    let times = report.verify().unwrap();
    assert_eq!(times.len(), 3);
    assert_eq!(inconsistency(&times), Some((0, 1)));
}
#[test]
fn full_tree_all_indices_and_non_power_of_two_batches() {
    let id = identity();
    for n in 1..=32 {
        let requests: Vec<_> = (0..n)
            .map(|i| request(&[i; 32], &id.root).unwrap())
            .collect();
        assert_eq!(requests[0].len(), 1036);
        let responses = id.respond(&requests, 1000, 3).unwrap();
        for (req, resp) in requests.iter().zip(responses) {
            assert!(resp.len() <= req.len());
            let time = verify_response(req, &resp, &id.root).unwrap();
            assert_eq!((time.midpoint, time.radius), (1000, 3));
        }
    }
}
#[test]
fn proofs_bind_the_entire_request_including_padding() {
    let id = identity();
    let req = request(&[1; 32], &id.root).unwrap();
    let resp = id
        .respond(std::slice::from_ref(&req), 1000, 3)
        .unwrap()
        .remove(0);
    let changed = replace_packet(&req, ZZZZ, vec![0; 916]);
    assert!(check_request(&changed, &id.root).is_ok());
    assert!(verify_response(&changed, &resp, &id.root).is_err());
    for (tag, value) in [
        (NONC, vec![0; 32]),
        (INDX, 1u32.to_le_bytes().to_vec()),
        (PATH, vec![0; 32]),
        (TYPE, vec![0; 4]),
        (SIG, vec![0; 64]),
    ] {
        assert!(verify_response(&req, &replace_packet(&resp, tag, value), &id.root).is_err());
    }
    assert!(verify_response(&req, &resp, &[0; 32]).is_err());
}
#[test]
fn signatures_certificate_and_signed_semantics_are_checked() {
    let id = identity();
    let req = request(&[1; 32], &id.root).unwrap();
    let resp = id
        .respond(std::slice::from_ref(&req), 1000, 3)
        .unwrap()
        .remove(0);
    let m = unpack(&resp).unwrap();
    for (t, v) in [
        (RADI, vec![0; 4]),
        (MIDP, 99u64.to_le_bytes().to_vec()),
        (MIDP, 2001u64.to_le_bytes().to_vec()),
        (VER, 2u32.to_le_bytes().to_vec()),
        (VERS, vec![0; 4]),
    ] {
        let srep = replace_message(m.required(SREP).unwrap(), t, v);
        let signer = SigningKey::from_bytes(&[29; 32]);
        let sig = signer.sign(&[b"Roughtime v1 response signature\0".as_slice(), &srep].concat());
        let resp = replace_packet(
            &replace_packet(&resp, SREP, srep),
            SIG,
            sig.to_bytes().to_vec(),
        );
        assert!(verify_response(&req, &resp, &id.root).is_err());
    }
    let mut cert = m.required(CERT).unwrap().to_vec();
    let last = cert.len() - 1;
    cert[last] ^= 1;
    assert!(verify_response(&req, &replace_packet(&resp, CERT, cert), &id.root).is_err());
    assert!(id.respond(std::slice::from_ref(&req), 1000, 0).is_err());
    assert!(id.respond(&[req], 99, 3).is_err());
}
#[test]
fn request_validation_and_unknown_extensions() {
    let id = identity();
    let req = request(&[3; 32], &id.root).unwrap();
    let m = unpack(&req).unwrap();
    let extended = packet(
        encode(vec![
            (VER, [1u32.to_le_bytes(), 9u32.to_le_bytes()].concat()),
            (TYPE, vec![0; 4]),
            (NONC, m.required(NONC).unwrap().to_vec()),
            (tag(b"NEW\0"), vec![5; 4]),
            (ZZZZ, vec![0; 1024]),
        ])
        .unwrap(),
    )
    .unwrap();
    let resp = id
        .respond(std::slice::from_ref(&extended), 1000, 3)
        .unwrap()
        .remove(0);
    assert!(verify_response(&extended, &resp, &id.root).is_ok());
    for (t, v) in [
        (TYPE, 1u32.to_le_bytes().to_vec()),
        (SRV, vec![0; 32]),
        (NONC, vec![0; 28]),
        (VER, vec![0; 4]),
        (VER, [1u32.to_le_bytes(), 1u32.to_le_bytes()].concat()),
        (ZZZZ, vec![1; 912]),
    ] {
        assert!(check_request(&replace_packet(&req, t, v), &id.root).is_err());
    }
    let short = packet(
        encode(vec![
            (VER, 1u32.to_le_bytes().to_vec()),
            (TYPE, vec![0; 4]),
            (NONC, vec![0; 32]),
        ])
        .unwrap(),
    )
    .unwrap();
    assert!(id.respond(&[short], 1000, 3).is_err());
}
#[test]
fn framing_offsets_duplicate_tags_and_version_limits() {
    assert!(Message::decode(&[0; 8]).is_err());
    let mut m = encode(vec![(VER, vec![1; 4]), (NONC, vec![2; 32])]).unwrap();
    for offset in [3, 1000, u32::MAX] {
        m[4..8].copy_from_slice(&offset.to_le_bytes());
        assert!(Message::decode(&m).is_err());
    }
    m[4..8].copy_from_slice(&4u32.to_le_bytes());
    m[12..16].copy_from_slice(&VER.to_le_bytes());
    assert!(Message::decode(&m).is_err());
    let mut p = request(&[0; 32], &identity().root).unwrap();
    p.push(0);
    assert!(unpack(&p).is_err());
    assert!(versions(&[]).is_err());
    assert!(versions(&[0; 132]).is_err());
    assert!(versions(&[2u32.to_le_bytes(), 1u32.to_le_bytes()].concat()).is_err());
}
#[test]
fn no_unused_index_bits_even_for_maximum_depth() {
    let id = identity();
    let reqs = (0..32)
        .map(|i| request(&[i; 32], &id.root).unwrap())
        .collect::<Vec<_>>();
    let resp = id.respond(&reqs, 1000, 3).unwrap().remove(0);
    assert!(
        verify_response(
            &reqs[0],
            &replace_packet(&resp, INDX, 32u32.to_le_bytes().to_vec()),
            &id.root
        )
        .is_err()
    );
    assert!(
        verify_response(
            &reqs[0],
            &replace_packet(&resp, PATH, vec![0; 1056]),
            &id.root
        )
        .is_err()
    );
}
#[test]
fn delegation_boundaries_key_mismatch_and_bounds() {
    let id = identity();
    let req = request(&[0; 32], &id.root).unwrap();
    for t in [100, 2000] {
        assert!(
            verify_response(
                &req,
                &id.respond(std::slice::from_ref(&req), t, 3).unwrap()[0],
                &id.root
            )
            .is_ok()
        );
    }
    let root = SigningKey::from_bytes(&[17; 32]);
    let online = SigningKey::from_bytes(&[29; 32]);
    assert!(certificate(&root, &online.verifying_key().to_bytes(), 2, 1).is_err());
    let cert = certificate(&root, &online.verifying_key().to_bytes(), 1, 2).unwrap();
    assert!(
        Identity::new(
            SigningKey::from_bytes(&[30; 32]),
            cert,
            root.verifying_key().to_bytes()
        )
        .is_err()
    );
    assert!(merkle(&[]).is_err());
    assert!(merkle(&vec![req; 33]).is_err());
}
#[test]
fn causality_handles_unsigned_overflow_without_wrapping() {
    let t = VerifiedTime {
        midpoint: 0,
        radius: 3,
    };
    assert_eq!(t.lower(), -3);
    let t = VerifiedTime {
        midpoint: u64::MAX,
        radius: u32::MAX,
    };
    assert!(t.upper() > u64::MAX as i128);
    assert!(
        inconsistency(&[
            VerifiedTime {
                midpoint: 10,
                radius: 3
            },
            VerifiedTime {
                midpoint: 4,
                radius: 3
            }
        ])
        .is_none()
    );
}
#[test]
fn tampered_evidence_is_not_malfeasance() {
    let mut report: Evidence =
        serde_json::from_str(include_str!("fixtures/rfc10049-appendix-b.json")).unwrap();
    report.responses[1].rand = Some(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        [0; 32],
    ));
    assert!(report.verify().is_err());
}
#[test]
fn retry_schedule_is_bounded_and_exponential() {
    use gnomon::client::retry_interval;
    assert_eq!(retry_interval(1).as_secs_f64(), 1.0);
    assert_eq!(retry_interval(2).as_secs_f64(), 1.5);
    assert_eq!(retry_interval(3).as_secs_f64(), 2.25);
    assert_eq!(retry_interval(u32::MAX).as_secs(), 86400);
}
proptest! {
    #[test]
    fn arbitrary_packets_never_panic(data in prop::collection::vec(any::<u8>(),0..5000)) {
        let _=Message::decode(&data); let _=unpack(&data); let _=check_request(&data,&[0;32]);
        let _=verify_response(&data,&data,&[0;32]);
    }
    #[test]
    fn aligned_codec_roundtrips(a in prop::collection::vec(any::<[u8;4]>(),0..50), b in prop::collection::vec(any::<u8>(),0..200)) {
        let a:Vec<_>=a.into_iter().flatten().collect();
        let encoded=encode(vec![(VER,a.clone()),(NONC,b.clone())]).unwrap();
        let decoded=Message::decode(&encoded).unwrap();
        prop_assert_eq!(decoded.required(VER).unwrap(),a); prop_assert_eq!(decoded.required(NONC).unwrap(),b);
    }
}
