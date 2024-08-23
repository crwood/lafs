use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

pub mod util;

pub use crate::util::base32;
pub use crate::util::hashutil;
pub use crate::util::netstring;

#[pyfunction]
#[pyo3(name = "b2a")]
fn base32_b2a(py: Python, b: &[u8]) -> PyObject {
    let result = base32::b2a(b);
    PyBytes::new_bound(py, &result).into()
}

#[pyfunction]
#[pyo3(name = "tagged_hash")]
#[pyo3(signature = (tag, val, truncate_to = 32))]
fn hashutil_tagged_hash(py: Python, tag: &[u8], val: &[u8], truncate_to: usize) -> PyObject {
    let result = hashutil::tagged_hash(tag, val, truncate_to);
    PyBytes::new_bound(py, &result).into()
}

#[pyfunction]
#[pyo3(name = "ssk_writekey_hash")]
fn hashutil_ssk_writekey_hash(py: Python, privkey: &[u8]) -> PyObject {
    let result = hashutil::ssk_writekey_hash(privkey);
    PyBytes::new_bound(py, &result).into()
}

#[pyfunction]
#[pyo3(name = "ssk_pubkey_fingerprint_hash")]
fn hashutil_ssk_pubkey_fingerprint_hash(py: Python, pubkey: &[u8]) -> PyObject {
    let result = hashutil::ssk_pubkey_fingerprint_hash(pubkey);
    PyBytes::new_bound(py, &result).into()
}

#[pyfunction]
#[pyo3(name = "netstring")]
fn netstring_netstring(py: Python, s: &[u8]) -> PyObject {
    let result = netstring::netstring(s);
    PyBytes::new_bound(py, &result).into()
}

#[pymodule]
fn lafs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let base32_module = PyModule::new_bound(m.py(), "base32")?;
    base32_module.add_function(wrap_pyfunction!(base32_b2a, &base32_module)?)?;

    let hashutil_module = PyModule::new_bound(m.py(), "hashutil")?;
    hashutil_module.add_function(wrap_pyfunction!(hashutil_tagged_hash, &hashutil_module)?)?;
    hashutil_module.add_function(wrap_pyfunction!(
        hashutil_ssk_writekey_hash,
        &hashutil_module
    )?)?;
    hashutil_module.add_function(wrap_pyfunction!(
        hashutil_ssk_pubkey_fingerprint_hash,
        &hashutil_module
    )?)?;

    let netstring_module = PyModule::new_bound(m.py(), "netstring")?;
    netstring_module.add_function(wrap_pyfunction!(netstring_netstring, &base32_module)?)?;

    let util_module = PyModule::new_bound(m.py(), "util")?;
    util_module.add_submodule(&base32_module)?;
    util_module.add_submodule(&hashutil_module)?;
    util_module.add_submodule(&netstring_module)?;
    m.add_submodule(&util_module)?;

    Ok(())
}

pub fn derive_lafs_mutable(private_key_pem: &str, format: &str) -> String {
    // TODO: Support pkcs8?
    let private_key = RsaPrivateKey::from_pkcs1_pem(private_key_pem).unwrap();
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
    use serde_yaml;

    #[test]
    fn test_derive_lafs_mutable() {
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
                let result = super::derive_lafs_mutable(key, format);
                let expected = vector["expected"].as_str().unwrap();
                assert_eq!(result, expected);
            }
        }
    }
}
