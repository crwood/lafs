use data_encoding::BASE32_NOPAD;

pub fn b2a(b: &[u8]) -> Vec<u8> {
    BASE32_NOPAD.encode(b).to_lowercase().into_bytes()
}

#[test]
fn test_b2a() {
    // Values from allmydata.test.test_base32
    assert_eq!(b2a(b"\x12\x34"), b"ci2a");
}
