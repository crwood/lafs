import pytest
from allmydata.util.base32 import b2a as allmydata_b2a
from allmydata.util.hashutil import \
    ssk_pubkey_fingerprint_hash as allmydata_ssk_pubkey_fingerprint_hash
from allmydata.util.hashutil import \
    ssk_writekey_hash as allmydata_ssk_writekey_hash
from allmydata.util.hashutil import tagged_hash as allmydata_tagged_hash

# Due to current limitations with pyo3, we can't import functions from
# child modules directly (in the form `from x.y import z`) and must
# instead import the parent module and access the function as an
# attribute (in the form `x.y.z`). See
# https://pyo3.rs/v0.22.2/module#python-submodules
# https://github.com/PyO3/pyo3/issues/759
# https://github.com/PyO3/pyo3/issues/1517#issuecomment-808664021
import lafs

b2a = lafs.util.base32.b2a
ssk_pubkey_fingerprint_hash = lafs.util.hashutil.ssk_pubkey_fingerprint_hash
ssk_writekey_hash = lafs.util.hashutil.ssk_writekey_hash
tagged_hash = lafs.util.hashutil.tagged_hash


@pytest.mark.parametrize(
    "tag, val, truncate_to, expected",
    # Values from allmydata.test.test_hashutil
    [
        (
            b"tag",
            b"hello world",
            32,
            b"yra322btzoqjp4ts2jon5dztgnilcdg6jgztgk7joi6qpjkitg2q",
        ),
        (
            b"different",
            b"hello world",
            32,
            b"kfbsfssrv2bvtp3regne6j7gpdjcdjwncewriyfdtt764o5oa7ta",
        ),
        (
            b"different",
            b"goodbye world",
            32,
            b"z34pzkgo36chbjz2qykonlxthc4zdqqquapw4bcaoogzvmmcr3zq",
        ),
    ],
)
def test_tagged_hash(tag, val, truncate_to, expected) -> None:
    assert allmydata_b2a(allmydata_tagged_hash(tag, val, truncate_to)) == expected
    assert b2a(tagged_hash(tag, val, truncate_to)) == expected


def test_ssk_writekey_hash() -> None:
    # Values from allmydata.test.test_hashutil
    input = b""
    expected = b"ykpgmdbpgbb6yqz5oluw2q26ye"
    assert allmydata_b2a(allmydata_ssk_writekey_hash(input)) == expected
    assert b2a(ssk_writekey_hash(input)) == expected


def test_ssk_pubkey_fingerprint_hash() -> None:
    # Values from allmydata.test.test_hashutil
    input = b""
    expected = b"3opzw4hhm2sgncjx224qmt5ipqgagn7h5zivnfzqycvgqgmgz35q"
    assert allmydata_b2a(allmydata_ssk_pubkey_fingerprint_hash(input)) == expected
    assert b2a(ssk_pubkey_fingerprint_hash(input)) == expected
