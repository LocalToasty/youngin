"""Convenience functions for reading and writing binascii formats"""

import base64

import bech32

from .exceptions import HeaderFailureException


def b64encode_no_pad(s: bytes) -> bytes:
    return base64.b64encode(s)[: (len(s) * 8 + 5) // 6]


def b64decode_no_pad(b: bytes) -> bytes:
    if b.endswith(b"="):
        raise HeaderFailureException("padding in base64 not allowed")
    if len(b) % 4 == 0:
        return base64.b64decode(b)

    decoded_len = (len(b) * 6) // 8
    decoded = base64.b64decode(b + b"A==")
    if decoded[decoded_len:] != b"\0":
        raise HeaderFailureException("non-canonical base64")
    return decoded[:decoded_len]


def bech32_encode(hrp: str, data: bytes) -> str:
    base32 = bech32.convertbits(data, frombits=8, tobits=5)
    assert base32 is not None
    return bech32.bech32_encode(hrp, data=base32)


def bech32_decode(hrp: str, data: str) -> bytes:
    hrpgot, decoded_data = bech32.bech32_decode(data)
    assert hrpgot == hrp
    assert decoded_data is not None
    data_bytes = bech32.convertbits(decoded_data, 5, 8, pad=False)
    assert data_bytes is not None
    return bytes(data_bytes)
