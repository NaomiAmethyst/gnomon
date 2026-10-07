#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = gnomon::wire::unpack(data);
    let _ = gnomon::wire::Message::decode(data);
    let _ = gnomon::crypto::check_request(data, &[0;32]);
    let split = data.len()/2;
    let _ = gnomon::crypto::verify_response(&data[..split], &data[split..], &[0;32]);
});
