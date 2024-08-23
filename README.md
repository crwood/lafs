# LAFS

_LAFS_ is an **experimental** Rust crate that provides a limited implementation of some parts of [Tahoe-LAFS](https://tahoe-lafs.org) -- the Least-Authority File Store. More specifically, it offers Rust implementations of the following functions (from the original Python `allmydata` package):

```
allmydata.util.base32.b2a
allmydata.util.hashutil.tagged_hash
allmydata.util.hashutil.ssk_pubkey_fingerprint_hash
allmydata.util.hashutil.ssk_writekey_hash
allmydata.util.netstring.netstring
```

Taken together, these provide just enough functionality to derive valid mutable capability strings/URIs that are fully compatible with the original (Python) implementation (as confirmed by testing against Tahoe-LAFS' own test vectors). As such, this library can be used to generate or recover cryptographic capabilities completely "offline" (i.e., without the need to interact with a running Tahoe-LAFS node) and/or in environments -- such as mobile -- where running a full `tahoe` node may be infeasible or undesirable.


## Usage

Although Tahoe-LAFS does not provide a Python API, for the sake of consistency with the original implementation, paths exposed by this crate strive to match the namespaces defined in the original `allmydata` Python package. For example, the Python `allmydata.util.base32.b2a` function can be called via the `lafs::util::base32::b2a` path in Rust.

Function signatures and types, likewise, aim to follow the original implementation as closely as possible (thus a Python function that returns a `bytes` of undefined length might return a `Vec<u8>` in Rust), however, given Python's dynamic type system and other fundamental language differences (like Python's exception system, "default" args., etc.), some concessions should be expected. When in doubt, consult the source code.


## Python bindings

In addition to the Rust crate, Python bindings are provided for each of the modules/functions defined by this library (using [pyo3](https://pyo3.rs/), however, due to the aforementioned essential language differences (as well as some [outstanding](https://github.com/PyO3/pyo3/issues/759) [issues](https://github.com/PyO3/pyo3/issues/1517) with pyo3 submodule imports), these should not be considered as suitable "drop-in" replacements for those defined by the `allmydata` Python package; these bindings are used mainly to support testing against the original implementation. (See the `test/` directory for examples.)
