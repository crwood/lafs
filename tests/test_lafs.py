from pathlib import Path

import yaml

from allmydata.util.base32 import b2a
from allmydata.util.hashutil import ssk_pubkey_fingerprint_hash, ssk_writekey_hash
from cryptography.hazmat.primitives import serialization

from lafs import derive_mutable_uri


def py_derive_mutable_uri(private_key_pem: str, format: str) -> str:
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


def test_derive_mutable_uri() -> None:

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
            expected = vector["expected"]
            assert py_derive_mutable_uri(key, format) == expected
            assert derive_mutable_uri(key, format) == expected
