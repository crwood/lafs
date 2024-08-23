pub fn netstring(s: &[u8]) -> Vec<u8> {
    format!("{}:{},", s.len(), std::str::from_utf8(s).unwrap()).into_bytes()
}

#[test]
fn test_netstring() {
    // Values from allmydata.test.test_netstring
    assert_eq!(netstring(b"abc"), b"3:abc,");
}
