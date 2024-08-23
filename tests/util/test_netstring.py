from allmydata.util.netstring import netstring as allmydata_netstring

# Due to current limitations with pyo3, we can't import functions from
# child modules directly (in the form `from x.y import z`) and must
# instead import the parent module and access the function as an
# attribute (in the form `x.y.z`). See
# https://pyo3.rs/v0.22.2/module#python-submodules
# https://github.com/PyO3/pyo3/issues/759
# https://github.com/PyO3/pyo3/issues/1517#issuecomment-808664021
import lafs

netstring = lafs.util.netstring.netstring


def test_netstring() -> None:
    # Values from allmydata.test.test_netstring
    input = b"abc"
    expected = b"3:abc,"
    assert allmydata_netstring(input) == expected
    assert netstring(input) == expected
