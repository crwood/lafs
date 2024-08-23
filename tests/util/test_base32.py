from allmydata.util.base32 import b2a as allmydata_b2a

# Due to current limitations with pyo3, we can't import functions from
# child modules directly (in the form `from x.y import z`) and must
# instead import the parent module and access the function as an
# attribute (in the form `x.y.z`). See
# https://pyo3.rs/v0.22.2/module#python-submodules
# https://github.com/PyO3/pyo3/issues/759
# https://github.com/PyO3/pyo3/issues/1517#issuecomment-808664021
import lafs

b2a = lafs.util.base32.b2a


def test_b2a() -> None:
    input = b"\x12\x34"
    expected = b"ci2a"
    assert allmydata_b2a(input) == expected
    assert b2a(input) == expected
