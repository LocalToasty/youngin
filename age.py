#!/usr/bin/env python3
import base64
import io
from collections.abc import Iterable
from dataclasses import dataclass
from io import RawIOBase
from pathlib import Path
from typing import BinaryIO, NewType, Optional, Protocol, Self, Sequence, Tuple

import bech32
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

__all__ = ["ReadAgeFile", "HeaderKey", "X25519Key", "ScryptKey"]


@dataclass
class Stanza:
    args: Sequence[bytes]
    body: bytes


FileKey = NewType("FileKey", bytes)


class HeaderKey(Protocol):
    def decode(self, stanza: Stanza) -> Optional[FileKey]: ...


class X25519Key:
    def __init__(self, identity: X25519PrivateKey) -> None:
        self._identity = identity

    @classmethod
    def from_age_secret_key(cls, age_secret_key: str) -> Self:
        identity = bech32_decode("age-secret-key-", age_secret_key)
        return cls(X25519PrivateKey.from_private_bytes(identity))

    def decode(self, stanza: Stanza) -> Optional[FileKey]:
        if stanza.args[0] != b"X25519":
            raise None
        if len(stanza.args) != 2:
            raise ValueError("X25519 stanza must have two arguments")

        recipient: X25519PublicKey = self._identity.public_key()
        ephemeral_share = base64.b64decode(stanza.args[1] + b"==")
        shared_secret = self._identity.exchange(
            X25519PublicKey.from_public_bytes(ephemeral_share)
        )

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=ephemeral_share + recipient.public_bytes_raw(),
            info=b"age-encryption.org/v1/X25519",
        )
        wrap_key = kdf.derive(key_material=shared_secret)
        wrap_chacha = ChaCha20Poly1305(wrap_key)
        try:
            file_key = wrap_chacha.decrypt(
                nonce=b"\0" * 12, data=stanza.body, associated_data=b""
            )
        except InvalidTag:
            return None

        if not any(shared_secret):
            return RuntimeError("shared secret may not be zero")

        return FileKey(file_key)

    @classmethod
    def from_age_keyfile(
        cls, file: BinaryIO | Path | str, keys: Iterable[HeaderKey] | None = None
    ) -> Iterable[Self]:
        if isinstance(file, (Path, str)):
            file = open(file, "rb")

        magic = file.peek(len(b"age-encryption.org/v1"))
        if magic.startswith(b"age-encryption.org/v1"):
            if not keys:
                raise RuntimeError("no age key to decrypt keyfile supplied")
            file = ReadAgeFile(file, keys)

        return [
            cls.from_age_secret_key(line.strip().decode())
            for line in file
            if not line.startswith(b"#") and line.strip()
        ]


def bech32_decode(hrp, data):
    hrpgot, data = bech32.bech32_decode(data)
    assert hrpgot == hrp
    return bytes(bech32.convertbits(data, 5, 8, pad=False))


class ScryptKey:
    def __init__(self, passphrase: bytes) -> None:
        self._passphrase = passphrase

    def decode(self, stanza: Stanza) -> Optional[FileKey]:
        if stanza.args[0] != b"scrypt":
            return None
        if len(stanza.args) != 3:
            raise ValueError("scrypt stanza must have three arguments")
        salt = base64.b64decode(stanza.args[1] + b"==")
        if len(salt) != 16:
            raise ValueError("scrypt salt must be 16 bytes long")

        work_factor_log2 = int(stanza.args[2])

        kdf = Scrypt(
            salt=b"age-encryption.org/v1/scrypt" + salt,
            length=32,
            n=2**work_factor_log2,
            r=8,
            p=1,
        )
        wrap_key = kdf.derive(self._passphrase)
        wrap_chacha = ChaCha20Poly1305(wrap_key)
        file_key = wrap_chacha.decrypt(
            nonce=b"\0" * 12, data=stanza.body, associated_data=b""
        )
        return FileKey(file_key)


DATA_CHUNK_SIZE = 64 * 2**10
TAG_SIZE = 16
ENCRYPTED_CHUNK_SIZE = DATA_CHUNK_SIZE + TAG_SIZE


class ReadAgeFile(io.BufferedIOBase):
    def __init__(
        self,
        file: RawIOBase | Path | str,
        keys: Iterable[HeaderKey],
    ) -> None:
        if isinstance(file, (Path, str)):
            self._fileobj = open(file, "rb")
        else:
            self._fileobj = file

        if self._fileobj.seekable():
            self._fileobj.seek(0)

        stanzas, header_lines, header_hmac = _parse_header(self._fileobj)

        # Find a matching stanza
        for stanza in stanzas:
            file_key = None
            for key in keys:
                file_key = key.decode(stanza)
                if file_key:
                    break
            if file_key:
                break
        else:
            raise RuntimeError("no matching key found")

        _verify_header(
            file_key=file_key, header_lines=header_lines, header_hmac=header_hmac
        )

        payload_key_nonce = self._fileobj.read(16)
        payload_hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=payload_key_nonce,
            info=b"payload",
        )

        payload_key = payload_hkdf.derive(file_key)
        self._payload_chacha = ChaCha20Poly1305(payload_key)

        self._off = 0
        self._counter = 0
        self._buf = b""
        self._next_encrypted_chunk = b""
        self._eof = False

        if self._fileobj.seekable():
            self._payload_start = self._fileobj.tell()

            self._file_len = self._fileobj.seek(0, 2)
            no_chunks = (
                self._file_len - self._payload_start + ENCRYPTED_CHUNK_SIZE - 1
            ) // ENCRYPTED_CHUNK_SIZE  # rounded up integer division
            self._cleartext_len = (
                self._file_len - self._payload_start - TAG_SIZE * no_chunks
            )

            self.seek(0)

    def detach(self) -> RawIOBase:
        fileobj = self._fileobj
        self._fileobj = None
        return fileobj

    def close(self) -> None:
        # Delete all attributes which may contain sensitive data
        del self._payload_chacha, self._buf, self._off, self._counter

        return self._fileobj.close()

    @property
    def closed(self):
        return self._fileobj.closed or not self._fileobj

    def seekable(self) -> bool:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self._fileobj.seekable()

    def seek(self, offset: int, whence: int = 0) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")

        if whence == 0:
            # Seek from start of file
            self._counter = offset // DATA_CHUNK_SIZE
            off = offset % DATA_CHUNK_SIZE
        elif whence == 1:
            # Seek from current position
            self._counter = self._counter + offset // DATA_CHUNK_SIZE
            off = (self._off + offset) % DATA_CHUNK_SIZE
        elif whence == 2:
            # Seek from end of file
            self._counter = (self._cleartext_len + offset) // DATA_CHUNK_SIZE
            off = (self._cleartext_len + offset) % DATA_CHUNK_SIZE
        else:
            raise NotImplementedError()

        self._fileobj.seek(
            pos := self._payload_start + self._counter * ENCRYPTED_CHUNK_SIZE
        )
        self._buf, self._off = b"", 0

        self._eof = pos >= self._file_len

        if off > 0:
            # We have to read a little bit to reach the middle of the chunk
            self.read(off)

        return self._counter * DATA_CHUNK_SIZE + self._off

    def read1(self, size: int = -1) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        elif self._eof:
            return b""

        if self._off >= len(self._buf):
            # We're out of data in our buffer. Time to read more
            if len(self._next_encrypted_chunk) < ENCRYPTED_CHUNK_SIZE + 1:
                # Our encrypted buffer isn't full yet; try to read some more
                data = self._fileobj.read(
                    2 * ENCRYPTED_CHUNK_SIZE - len(self._next_encrypted_chunk)
                )
                self._next_encrypted_chunk += data

                if not data:
                    if not self._next_encrypted_chunk:
                        if self._counter > 0:
                            raise RuntimeError(
                                "the last chunk must not be empty unless the file is empty!"
                            )
                        else:
                            # We've reached the EOF of an empty file
                            return b""
                elif len(self._next_encrypted_chunk) < ENCRYPTED_CHUNK_SIZE + 1:
                    # Still not enough data.  The user has to call read1() again.
                    # We need the additional byte to find out whether we're
                    # currently in the last chunk.
                    return b""

            # We have enough to decrypt something!
            cyphertext = self._next_encrypted_chunk[
                : min(ENCRYPTED_CHUNK_SIZE, len(self._next_encrypted_chunk))
            ]
            self._buf = self._payload_chacha.decrypt(
                nonce=_nonce(
                    self._counter,
                    last=len(self._next_encrypted_chunk) <= ENCRYPTED_CHUNK_SIZE,
                ),
                data=cyphertext,
                associated_data=b"",
            )

            self._next_encrypted_chunk = self._next_encrypted_chunk[len(cyphertext) :]
            self._counter += 1
            self._off = 0

        # Now return as much as requested from our buffer
        if size < 0:
            end = len(self._buf)
        else:
            end = min(self._off + size, len(self._buf))

        res = self._buf[self._off : end]
        self._off = end

        self._eof = self._off == len(self._buf) and not self._next_encrypted_chunk

        return res

    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            parts = []
            while not self._eof:
                parts.append(self.read1())
            return b"".join(parts)
        else:
            parts, bytes_so_far = [], 0
            while not self._eof and bytes_so_far < size:
                parts.append(self.read1(size - bytes_so_far))
                bytes_so_far += len(parts[-1])
            return b"".join(parts)

    def readable(self) -> bool:
        return self._fileobj.readable()

    def tell(self) -> int:
        return (self._counter - 1) * DATA_CHUNK_SIZE + self._off


def _nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\1" if last else b"\0")


def _parse_header(file: BinaryIO) -> Tuple[Iterable[Stanza], bytes, bytes]:
    header_lines = []
    v1_line = next(file)[:-1]
    if v1_line != b"age-encryption.org/v1":
        raise RuntimeError("did not find age header `age-encryption.org/v1`")
    header_lines.append(v1_line)

    stanzas = []

    while True:
        line = next(file)[:-1]
        if line.startswith(b"-> "):
            header_lines.append(line)
            # Stanza
            args = line.split(b" ")[1:]
            body_lines = []
            while line := next(file)[:-1]:
                header_lines.append(line)
                body_lines.append(line)
                if len(line) < 64:
                    break
            body = base64.b64decode(b"".join(body_lines) + b"==")
            stanzas.append(Stanza(args, body))
        elif line.startswith(b"---"):
            # Start of header HMAC
            header_hmac_base64 = line.split(b" ")[1]
            header_hmac = base64.b64decode(header_hmac_base64 + b"==")
            header_lines.append(b"---")

            return stanzas, b"\n".join(header_lines), header_hmac
        else:
            raise RuntimeError("unexcepted start of line in header")


def _verify_header(file_key: FileKey, header_lines: bytes, header_hmac: bytes) -> None:
    hmac_hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=b"header",
    )
    hmac_key = hmac_hkdf.derive(key_material=file_key)

    h = hmac.HMAC(key=hmac_key, algorithm=hashes.SHA256())
    h.update(header_lines)
    h.verify(header_hmac)


if __name__ == "__main__":
    import sys
    from argparse import ArgumentParser
    from getpass import getpass

    parser = ArgumentParser(description="decrypt age file")
    # TODO Doesn't do anything yet, to be used when we can actually encrypt
    parser.add_argument("--decrypt", "-d", action="store_true")
    parser.add_argument(
        "-o",
        "--output",
        type=lambda fn: open(fn, "wb"),
        default=sys.stdout.buffer,
    )
    parser.add_argument(
        "-i",
        "--identity",
        default=[],
        action="append",
    )
    parser.add_argument("input", default=sys.stdin.buffer, nargs="?")
    args = parser.parse_args()

    keys = []
    if args.identity:
        for identity_file_path in args.identity:
            with open(identity_file_path, "rb") as identity_file:
                magic = identity_file.peek(len(b"age-encryption.org/v1"))
                if magic.startswith(b"age-encryption.org/v1"):
                    passphrase = getpass(f"Enter passphrase for {identity_file_path}: ")
                    keys += X25519Key.from_age_keyfile(identity_file)
    else:
        keys = [ScryptKey(getpass(f"Enter passphrase: ").encode())]

    with ReadAgeFile(args.input, keys=keys) as agefile:
        while chunk := agefile.read(DATA_CHUNK_SIZE):
            try:
                args.output.write(chunk)
            except BrokenPipeError:
                break
