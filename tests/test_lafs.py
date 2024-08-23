from pathlib import Path

import pytest
import yaml

from allmydata.util.base32 import b2a
from allmydata.util.hashutil import (
    _SHA256d_Hasher,  # XXX
    ssk_pubkey_fingerprint_hash,
    ssk_writekey_hash,
)
from cryptography.hazmat.primitives import serialization


@pytest.mark.parametrize("data, expected", [
    (b"", b"lx3obytwcnm5gcucoucy4km7zqbycu2fix2vz5b6igmd6xkmsrla"),
    (b"test", b"svgvusp5odm3rpg3gxjfejtyfgkx67xx7jwhj6eedg64l2bcbh2a"),
])
def test_sha256d(data, expected) -> None:
    hasher = _SHA256d_Hasher()
    hasher.update(data)
    digest = hasher.digest()
    assert b2a(digest) == expected


def derive_lafs_mutable(private_key_pem: str, format: str) -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
    )
    public_key = private_key.public_key()

    privkey_der_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pubkey_der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    writekey = b2a(ssk_writekey_hash(privkey_der_bytes)).decode()
    fingerprint = b2a(ssk_pubkey_fingerprint_hash(pubkey_der_bytes)).decode()

    return f"URI:{format}:{writekey}:{fingerprint}"


def test_derive_lafs_mutable() -> None:
    with open(Path(__file__).parent / "vectors" / "lafs.yaml") as f:
        data = yaml.safe_load(f)
    for vector in data["vector"]:
        kind = vector["format"]["kind"]
        if kind == "ssk":
            key = vector["format"]["params"]["key"]
            format = vector["format"]["params"]["format"]
            if format == "sdmf":
                format = "SSK"
            elif format == "mdmf":
                format = "MDMF"
            else:
                raise ValueError(f"Unknown format: {format}")
            result = derive_lafs_mutable(key, format)
            expected = vector["expected"]
            assert result == expected
