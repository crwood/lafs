pub fn netstring(s: &[u8]) -> Vec<u8> {
    // what python does here is a little weird: it stuffs the length,
    // as ascii bytes that represent the number, then a colon, then
    // arbitrary bytes (usually 32 random-looking ones), then a single
    // comma byte
    let tag = format!("{}:", s.len());
    // stuff byte-sequences together; better way?
    [tag.as_bytes(), s, b","].concat()
}

#[test]
fn test_netstring() {
    // Values from allmydata.test.test_netstring
    assert_eq!(netstring(b"abc"), b"3:abc,");
    assert_eq!(netstring(b"\x80"), b"1:\x80,");
}
