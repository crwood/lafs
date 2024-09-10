use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

pub mod util;

pub use crate::util::base32;
pub use crate::util::hashutil;
pub use crate::util::netstring;

#[pymodule]
mod lafs {
    use super::*;

    #[pymodule]
    mod util {
        use super::*;

        #[pymodule]
        mod base32 {
            use super::*;
            use crate::util::base32;

            #[pyfunction]
            fn b2a(py: Python, b: &[u8]) -> PyObject {
                let result = base32::b2a(b);
                PyBytes::new_bound(py, &result).into()
            }
        }

        #[pymodule]
        mod hashutil {
            use super::*;
            use crate::util::hashutil;

            #[pyfunction]
            #[pyo3(signature = (tag, val, truncate_to = 32))]
            fn tagged_hash(py: Python, tag: &[u8], val: &[u8], truncate_to: usize) -> PyObject {
                let result = hashutil::tagged_hash(tag, val, truncate_to);
                PyBytes::new_bound(py, &result).into()
            }

            #[pyfunction]
            fn ssk_writekey_hash(py: Python, privkey: &[u8]) -> PyObject {
                let result = hashutil::ssk_writekey_hash(privkey);
                PyBytes::new_bound(py, &result).into()
            }

            #[pyfunction]
            fn ssk_pubkey_fingerprint_hash(py: Python, pubkey: &[u8]) -> PyObject {
                let result = hashutil::ssk_pubkey_fingerprint_hash(pubkey);
                PyBytes::new_bound(py, &result).into()
            }
        }

        #[pymodule]
        mod netstring {
            use super::*;
            use crate::util::netstring;

            #[pyfunction]
            #[pyo3(name = "netstring")]
            fn py_netstring(py: Python, s: &[u8]) -> PyObject {
                let result = netstring::netstring(s);
                PyBytes::new_bound(py, &result).into()
            }
        }
    }
}

pub fn derive_lafs_mutable(private_key_pem: &str, format: &str) -> String {
    let private_key = match RsaPrivateKey::from_pkcs1_pem(private_key_pem) {
        Ok(key) => key,
        Err(_) => RsaPrivateKey::from_pkcs8_pem(private_key_pem).unwrap(),
    };
    let public_key = private_key.to_public_key();

    let privkey_der = private_key.to_pkcs8_der().unwrap();
    let privkey_der_bytes = privkey_der.as_bytes();

    let pubkey_der = public_key.to_public_key_der().unwrap();
    let pubkey_der_bytes = pubkey_der.as_bytes();

    let writekey = hashutil::ssk_writekey_hash(privkey_der_bytes);
    let fingerprint = hashutil::ssk_pubkey_fingerprint_hash(pubkey_der_bytes);

    let writekey_b32 = base32::b2a(&writekey);
    let fingerprint_b32 = base32::b2a(&fingerprint);

    let writekey_b32_str = String::from_utf8(writekey_b32).unwrap();
    let fingerprint_b32_str = String::from_utf8(fingerprint_b32).unwrap();

    format!(
        "URI:{}:{}:{}",
        format, writekey_b32_str, fingerprint_b32_str
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::LineEnding;
    use serde_yaml;

    fn generate_rsa_private_key() -> RsaPrivateKey {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA private key")
    }

    #[test]
    fn test_derive_lafs_mutable_from_pkcs1() {
        let private_key = generate_rsa_private_key();
        let pem_pkcs1 = private_key.to_pkcs1_pem(LineEnding::LF).unwrap();
        let result = derive_lafs_mutable(&pem_pkcs1, "SSK");
        assert_eq!(result.starts_with("URI:SSK:"), true);
    }

    #[test]
    fn test_derive_lafs_mutable_from_pkcs8() {
        let private_key = generate_rsa_private_key();
        let pem_pkcs8 = private_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let result = derive_lafs_mutable(&pem_pkcs8, "SSK");
        assert_eq!(result.starts_with("URI:SSK:"), true);
    }

    #[test]
    fn test_derive_lafs_mutable_pkcs1_eq_pkcs8() {
        let private_key = generate_rsa_private_key();
        let pem_pkcs1 = private_key.to_pkcs1_pem(LineEnding::LF).unwrap();
        let pem_pkcs8 = private_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let result_pkcs1 = derive_lafs_mutable(&pem_pkcs1, "SSK");
        let result_pkcs8 = derive_lafs_mutable(&pem_pkcs8, "SSK");
        assert_eq!(result_pkcs1, result_pkcs8);
    }

    #[test]
    fn test_derive_lafs_mutable_from_vectors() {
        let contents = std::fs::read_to_string("tests/vectors/lafs.yaml").unwrap();
        let data: serde_yaml::Value = serde_yaml::from_str(&contents).unwrap();
        for vector in data["vector"].as_sequence().unwrap() {
            let vector = vector.as_mapping().unwrap();
            let kind = vector["format"]["kind"].as_str().unwrap();
            if kind == "ssk" {
                let key = vector["format"]["params"]["key"].as_str().unwrap();
                let format = vector["format"]["params"]["format"].as_str().unwrap();
                let format = match format {
                    "sdmf" => "SSK",
                    "mdmf" => "MDMF",
                    _ => panic!("Unknown format: {:?}", format),
                };
                let result = derive_lafs_mutable(key, format);
                let expected = vector["expected"].as_str().unwrap();
                assert_eq!(result, expected);
            }
        }
    }
}
