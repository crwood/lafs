use bitcoin_hashes::{sha256d, Hash, HashEngine};

use crate::util::netstring::netstring;

#[cfg(test)]
use crate::base32::b2a;


#[test]
fn test_sha256d() {
    assert_eq!(
        b2a(&sha256d::Hash::hash(b"test").to_byte_array()),
        b"svgvusp5odm3rpg3gxjfejtyfgkx67xx7jwhj6eedg64l2bcbh2a"
    );
    assert_eq!(
        b2a(&sha256d::Hash::hash(b"").to_byte_array()),
        b"lx3obytwcnm5gcucoucy4km7zqbycu2fix2vz5b6igmd6xkmsrla"
    );
}

pub fn tagged_hash(tag: &[u8], val: &[u8], truncate_to: usize) -> Vec<u8> {
    if truncate_to > 32 {
        panic!("truncate_to must be <= 32");
    }
    let mut engine = sha256d::Hash::engine();
    engine.input(&netstring(tag));
    engine.input(val);
    sha256d::Hash::from_engine(engine).to_byte_array()[0..truncate_to].to_vec()
}

#[test]
fn test_tagged_hash() {
    // Values from allmydata.test.test_hashutil
    assert_eq!(
        b2a(&tagged_hash(b"tag", b"hello world", 32)),
        b"yra322btzoqjp4ts2jon5dztgnilcdg6jgztgk7joi6qpjkitg2q"
    );
    assert_eq!(
        b2a(&tagged_hash(b"different", b"hello world", 32)),
        b"kfbsfssrv2bvtp3regne6j7gpdjcdjwncewriyfdtt764o5oa7ta"
    );
    assert_eq!(
        b2a(&tagged_hash(b"different", b"goodbye world", 32)),
        b"z34pzkgo36chbjz2qykonlxthc4zdqqquapw4bcaoogzvmmcr3zq"
    )
}

const MUTABLE_WRITEKEY_TAG: &[u8] = b"allmydata_mutable_privkey_to_writekey_v1";
const MUTABLE_PUBKEY_TAG: &[u8] = b"allmydata_mutable_pubkey_to_fingerprint_v1";

const KEYLEN: usize = 16;

pub fn ssk_writekey_hash(privkey: &[u8]) -> [u8; KEYLEN] {
    tagged_hash(MUTABLE_WRITEKEY_TAG, privkey, KEYLEN)
        .try_into()
        .unwrap()
}

#[test]
fn test_ssk_writekey_hash() {
    // Values from allmydata.test.test_hashutil
    assert_eq!(b2a(&ssk_writekey_hash(b"")), b"ykpgmdbpgbb6yqz5oluw2q26ye");
}

pub fn ssk_pubkey_fingerprint_hash(pubkey: &[u8]) -> [u8; 32] {
    tagged_hash(MUTABLE_PUBKEY_TAG, pubkey, 32)
        .try_into()
        .unwrap()
}

#[test]
fn test_ssk_pubkey_fingerprint_hash() {
    // Values from allmydata.test.test_hashutil
    assert_eq!(
        b2a(&ssk_pubkey_fingerprint_hash(b"")),
        b"3opzw4hhm2sgncjx224qmt5ipqgagn7h5zivnfzqycvgqgmgz35q"
    );
}
