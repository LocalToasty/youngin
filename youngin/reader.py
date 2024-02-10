"""Read age-encrypted files."""

import io
import os
from collections.abc import Iterable
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .binascii import b64decode_no_pad
from .exceptions import (
    HeaderFailureException,
    HmacFailureException,
    NoMatchException,
    PayloadFailureException,
)
from .identity import FileKey, Identity, ScryptPassphrase, Stanza

__all__ = ["AgeReader"]

DATA_CHUNK_SIZE = 64 * 2**10
TAG_SIZE = 16
ENCRYPTED_CHUNK_SIZE = DATA_CHUNK_SIZE + TAG_SIZE


class AgeReader(io.BufferedIOBase):
    def __init__(
        self,
        file: io.IOBase | Path | str,
        identities: Iterable[Identity],
    ) -> None:
        if isinstance(file, (Path, str)):
            self._fileobj: io.IOBase = open(file, "rb")
        else:
            self._fileobj = file

        stanzas, header_lines, header_hmac = _parse_header(self._fileobj)

        # Find a matching stanza
        for stanza in stanzas:
            file_key = None
            for identity in identities:
                file_key = identity.decode(stanza)
                if file_key:
                    if (
                        isinstance(identity, ScryptPassphrase)
                        and len(list(identities)) > 1
                    ):
                        raise HeaderFailureException(
                            "scrypt stanzas must be alone in the header"
                        )
                    break
            if file_key:
                break
        else:
            raise NoMatchException("no matching key found")

        _verify_header(
            file_key=file_key, header_lines=header_lines, header_hmac=header_hmac
        )

        payload_key_nonce = self._fileobj.read(16)
        if len(payload_key_nonce) != 16:
            raise HeaderFailureException("short nonce")
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

            self._file_len = self._fileobj.seek(0, os.SEEK_END)
            no_chunks = (
                self._file_len - self._payload_start + ENCRYPTED_CHUNK_SIZE - 1
            ) // ENCRYPTED_CHUNK_SIZE  # rounded up integer division
            self._cleartext_len = (
                self._file_len - self._payload_start - TAG_SIZE * no_chunks
            )

            # Seek to the start of the payload
            self.seek(0, os.SEEK_SET)

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

        match whence:
            case os.SEEK_SET:
                # Seek from start of file
                self._counter = offset // DATA_CHUNK_SIZE
                off = offset % DATA_CHUNK_SIZE
            case os.SEEK_CUR:
                # Seek from current position
                self._counter = self._counter + offset // DATA_CHUNK_SIZE
                off = (self._off + offset) % DATA_CHUNK_SIZE
            case os.SEEK_END:
                # Seek from end of file
                self._counter = (self._cleartext_len + offset) // DATA_CHUNK_SIZE
                off = (self._cleartext_len + offset) % DATA_CHUNK_SIZE
            case _:
                raise NotImplementedError()

        self._fileobj.seek(
            pos := self._payload_start + self._counter * ENCRYPTED_CHUNK_SIZE
        )
        self._buf, self._off = b"", 0

        self._eof = pos >= self._file_len
        if self._eof and self._counter == 0:
            raise PayloadFailureException("no chunks")

        if off > 0:
            # We have to read a little bit to reach the middle of the chunk
            self.read(off)

        return self._counter * DATA_CHUNK_SIZE + self._off

    def read1(self, size: int = -1) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed file.")

        if self._eof:
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
                        assert False, "not reachable"
                elif len(self._next_encrypted_chunk) < ENCRYPTED_CHUNK_SIZE + 1:
                    # Still not enough data.  The user has to call read1() again.
                    # We need the additional byte to find out whether we're
                    # currently in the last chunk.
                    return b""

            # We have enough to decrypt something!
            cyphertext = self._next_encrypted_chunk[
                : min(ENCRYPTED_CHUNK_SIZE, len(self._next_encrypted_chunk))
            ]
            try:
                self._buf = self._payload_chacha.decrypt(
                    nonce=_nonce(
                        self._counter,
                        last=len(self._next_encrypted_chunk) <= ENCRYPTED_CHUNK_SIZE,
                    ),
                    data=cyphertext,
                    associated_data=b"",
                )
            except InvalidTag as e:
                raise PayloadFailureException(e) from e

            if self._counter > 0 and not self._buf:
                raise PayloadFailureException(
                    "final STREAM chunk can't be empty unless whole payload is empty"
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
        if self._eof:
            if self._counter == 0:
                raise PayloadFailureException("no chunks")
        return res

    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            parts = []
            while not self._eof:
                parts.append(self.read1())
            return b"".join(parts)

        # Read exactly `size` bytes
        parts, bytes_so_far = [], 0
        while not self._eof and bytes_so_far < size:
            parts.append(self.read1(size - bytes_so_far))
            bytes_so_far += len(parts[-1])
        return b"".join(parts)

    def readable(self) -> bool:
        return self._fileobj.readable()

    def tell(self) -> int:
        return (self._counter - 1) * DATA_CHUNK_SIZE + self._off

    def peek(self, size: int = 0) -> bytes:
        return self._buf[self._off : min(self._off + size, len(self._buf))]


def _nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\1" if last else b"\0")


def _parse_header(file: io.IOBase) -> tuple[Iterable[Stanza], bytes, bytes]:
    header_lines = []
    v1_line = next(file)[:-1]
    if v1_line != b"age-encryption.org/v1":
        raise HeaderFailureException("did not find age header `age-encryption.org/v1`")
    header_lines.append(v1_line)

    stanzas = []

    while True:
        line = next(file)[:-1]

        if line.startswith(b"-> "):
            header_lines.append(line)
            # Stanza
            args = line.split(b" ")[1:]
            body_lines = []
            while True:
                line = next(file)[:-1]
                if len(line) > 64:
                    raise HeaderFailureException(
                        "stanza body lines must be shorter than 64 characters"
                    )
                header_lines.append(line)
                body_lines.append(line)
                if len(line) < 64:
                    break

            body_bytes = b"".join(body_lines)
            body = b64decode_no_pad(body_bytes)
            stanzas.append(Stanza(args, body))

        elif line.startswith(b"---"):
            # Start of header HMAC
            if b" " not in line:
                raise HeaderFailureException("could not find header HMAC")
            header_hmac_base64 = line.split(b" ", maxsplit=1)[1]
            if len(header_hmac_base64) != 43:
                raise HeaderFailureException("header HMAC has wrong length")
            header_hmac = b64decode_no_pad(header_hmac_base64)
            header_lines.append(b"---")

            return stanzas, b"\n".join(header_lines), header_hmac
        else:
            raise HeaderFailureException("unexcepted start of line in header")


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
    try:
        h.verify(header_hmac)
    except InvalidSignature as e:
        raise HmacFailureException(e) from e
