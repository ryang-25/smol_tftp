use smol_tftp::packet;

/// Assert that multiple nul bytes fails netascii validation.
#[test]
fn test_multiple_nul() {
    packet::netascii_from_u8("abc\0def\0".as_bytes()).unwrap();
}
