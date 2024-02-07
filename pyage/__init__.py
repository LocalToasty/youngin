import base64
import io
import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, NewType, Optional, Protocol, Self, Sequence

import bech32
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

__all__ = [
    "Identity",
    "Recipient",
    "X25519Identity",
    "X25519Recipient",
    "ScryptPassphrase",
    "AgeReader",
    "AgeWriter",
]

DATA_CHUNK_SIZE = 64 * 2**10
TAG_SIZE = 16
ENCRYPTED_CHUNK_SIZE = DATA_CHUNK_SIZE + TAG_SIZE
MAX_WORK_FACTOR_LOG_2 = 20


class Stanza:
    def __init__(self, args: Sequence[bytes], body: bytes) -> None:
        if not args:
            raise HeaderFailureException("empty stanza is not allowed")
        if not all(args):
            raise HeaderFailureException("empty stanza argument")
        try:
            [arg.decode(encoding="ascii") for arg in args]
        except UnicodeDecodeError:
            raise HeaderFailureException("stanza args have to be all ascii")
        self.args = args
        self.body = body

    def __bytes__(self) -> bytes:
        arg_bytes = b"-> " + b" ".join(self.args)
        body_bytes = b64encode_no_pad(self.body)
        body_lines = [
            body_bytes[i : min(i + 64, len(body_bytes))]
            for i in range(0, len(body_bytes), 64)
        ]
        if not body_lines or len(body_lines[-1]) == 64:
            body_lines.append(b"")
        return b"\n".join([arg_bytes, b"\n".join(body_lines)])


FileKey = NewType("FileKey", bytes)


class Identity(Protocol):
    def decode(self, stanza: Stanza) -> Optional[FileKey]: ...


class Recipient(Protocol):
    def stanza(self, file_key: FileKey) -> Stanza: ...


class X25519Identity:
    def __init__(self, identity: X25519PrivateKey) -> None:
        self._identity = identity

    def recipient(self) -> "X25519Recipient":
        return X25519Recipient(self._identity.public_key().public_bytes_raw())

    @classmethod
    def from_secret_key(cls, age_secret_key: str) -> Self:
        identity = bech32_decode("age-secret-key-", age_secret_key)
        return cls(X25519PrivateKey.from_private_bytes(identity))

    def decode(self, stanza: Stanza) -> Optional[FileKey]:
        if stanza.args[0] != b"X25519":
            return None
        if len(stanza.args) != 2:
            raise HeaderFailureException("X25519 stanza must have two arguments")

        recipient: X25519PublicKey = self._identity.public_key()
        ephemeral_share = b64decode_no_pad(stanza.args[1])
        if len(ephemeral_share) != 32:
            raise HeaderFailureException("X25519 share is short")
        try:
            shared_secret = self._identity.exchange(
                X25519PublicKey.from_public_bytes(ephemeral_share)
            )
        except ValueError as e:
            raise HeaderFailureException(e)

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
        if len(file_key) != 16:
            raise HeaderFailureException("the file key must be 16 bytes long")

        return FileKey(file_key)

    @classmethod
    def from_keyfile(
        cls,
        file: io.BufferedReader | Path | str,
        identities: Iterable[Identity] | None = None,
    ) -> Iterable[Self]:
        if isinstance(file, (Path, str)):
            file = open(file, "rb")

        magic = file.peek(len(b"age-encryption.org/v1"))
        if magic.startswith(b"age-encryption.org/v1"):
            if not identities:
                raise RuntimeError("no age key to decrypt keyfile supplied")
            file = AgeReader(file, identities)

        return [
            cls.from_secret_key(line.strip().decode())
            for line in file
            if not line.startswith(b"#") and line.strip()
        ]


class X25519Recipient:
    def __init__(self, public_key_bytes: bytes) -> None:
        self._recipient = X25519PublicKey.from_public_bytes(public_key_bytes)

    @classmethod
    def from_public_key(cls, age_recipient: str) -> Self:
        return cls(public_key_bytes=bech32_decode("age", age_recipient))

    def stanza(self, file_key: FileKey) -> Stanza:
        ephemeral_secret = X25519PrivateKey.generate()
        ephemeral_share = ephemeral_secret.public_key()
        shared_secret = ephemeral_secret.exchange(self._recipient)
        if not any(shared_secret):
            raise RuntimeError("shared secret may not be zero")

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=ephemeral_share.public_bytes_raw()
            + self._recipient.public_bytes_raw(),
            info=b"age-encryption.org/v1/X25519",
        )
        wrap_key = kdf.derive(shared_secret)
        wrap_chacha = ChaCha20Poly1305(wrap_key)
        body = wrap_chacha.encrypt(nonce=b"\0" * 12, data=file_key, associated_data=b"")
        return Stanza(
            args=[b"X25519", b64encode_no_pad(ephemeral_share.public_bytes_raw())],
            body=body,
        )


class ScryptPassphrase:
    def __init__(self, passphrase: bytes) -> None:
        self._passphrase = passphrase

    def decode(self, stanza: Stanza) -> Optional[FileKey]:
        if stanza.args[0] != b"scrypt":
            return None
        if len(stanza.args) != 3:
            raise HeaderFailureException("scrypt stanza must have three arguments")
        salt = b64decode_no_pad(stanza.args[1])
        if len(salt) != 16:
            raise HeaderFailureException("scrypt salt must be 16 bytes long")

        if not re.match(r"^[1-9][0-9]*$", stanza.args[2].decode()):
            raise HeaderFailureException("work factor needs to be a positive integer")
        work_factor_log2 = int(stanza.args[2])
        if work_factor_log2 > MAX_WORK_FACTOR_LOG_2 or work_factor_log2 <= 0:
            raise HeaderFailureException("work factor too high or low")

        kdf = Scrypt(
            salt=b"age-encryption.org/v1/scrypt" + salt,
            length=32,
            n=2**work_factor_log2,
            r=8,
            p=1,
        )
        wrap_key = kdf.derive(self._passphrase)
        wrap_chacha = ChaCha20Poly1305(wrap_key)
        try:
            file_key = wrap_chacha.decrypt(
                nonce=b"\0" * 12, data=stanza.body, associated_data=b""
            )
        except InvalidTag:
            return None
        if len(file_key) != 16:
            raise HeaderFailureException("the file key must be 16 bytes long")
        return FileKey(file_key)

    def stanza(self, file_key: FileKey, work_factor_log2: int = 18) -> Stanza:
        salt = secrets.token_bytes(16)
        kdf = Scrypt(
            salt=b"age-encryption.org/v1/scrypt" + salt,
            length=32,
            n=2**work_factor_log2,
            r=8,
            p=1,
        )
        wrap_key = kdf.derive(self._passphrase)
        wrap_chacha = ChaCha20Poly1305(wrap_key)
        body = wrap_chacha.encrypt(nonce=b"\0" * 12, data=file_key, associated_data=b"")

        return Stanza(
            args=[b"scrypt", b64encode_no_pad(salt), str(work_factor_log2).encode()],
            body=body,
        )


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


__all__ = [
    "AgeReader",
    "AgeWriter",
]


class AgeReader(io.BufferedReader):
    def __init__(
        self,
        file: io.IOBase | Path | str,
        identities: Iterable[Identity],
    ) -> None:
        if isinstance(file, (Path, str)):
            self._fileobj: io.IOBase = open(file, "rb")
        else:
            self._fileobj = file

        if self._fileobj.seekable():
            self._fileobj.seek(0)

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

            self._file_len = self._fileobj.seek(0, 2)
            no_chunks = (
                self._file_len - self._payload_start + ENCRYPTED_CHUNK_SIZE - 1
            ) // ENCRYPTED_CHUNK_SIZE  # rounded up integer division
            self._cleartext_len = (
                self._file_len - self._payload_start - TAG_SIZE * no_chunks
            )

            self.seek(0)

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
        if self._eof and self._counter == 0:
            raise PayloadFailureException("no chunks")

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
                raise PayloadFailureException(e)

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


class PayloadFailureException(Exception):
    pass


class HeaderFailureException(Exception):
    pass


class NoMatchException(Exception):
    pass


class HmacFailureException(Exception):
    pass


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
        raise HmacFailureException(e)


class AgeWriter(io.BufferedIOBase):
    def __init__(
        self,
        file: BinaryIO | Path | str,
        *,
        recipients: Iterable[Recipient],
    ) -> None:
        if isinstance(file, (Path, str)):
            self._fileobj: BinaryIO = open(file, "wb")
        else:
            self._fileobj = file

        header_parts = [b"age-encryption.org/v1"]

        payload_nonce = secrets.token_bytes(16)
        file_key = FileKey(secrets.token_bytes(16))
        payload_hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=payload_nonce,
            info=b"payload",
        )
        payload_key = payload_hkdf.derive(file_key)

        if (
            any(isinstance(recipient, ScryptPassphrase) for recipient in recipients)
            and len(list(recipients)) > 1
        ):
            raise ValueError("scrypt passphrase must be sole recipient if present")

        for recipient in recipients:
            header_parts.append(bytes(recipient.stanza(file_key)))
        header_parts.append(b"---")
        header_bytes = b"\n".join(header_parts)

        hmac_hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"",
            info=b"header",
        )
        hmac_key = hmac_hkdf.derive(key_material=file_key)

        h = hmac.HMAC(key=hmac_key, algorithm=hashes.SHA256())
        h.update(header_bytes)
        digest = h.finalize()

        writeall(self._fileobj, header_bytes)
        writeall(self._fileobj, b" " + b64encode_no_pad(digest) + b"\n")
        writeall(self._fileobj, payload_nonce)

        self._buf = b""
        self._counter = 0
        self._payload_chacha = ChaCha20Poly1305(payload_key)

    def close(self) -> None:
        if self.closed:
            return

        # Write whatever is left in the buffer
        assert len(self._buf) <= DATA_CHUNK_SIZE
        cyphertext = self._payload_chacha.encrypt(
            nonce=_nonce(counter=self._counter, last=True),
            data=self._buf,
            associated_data=b"",
        )
        writeall(self._fileobj, cyphertext)

        return self._fileobj.close()

    @property
    def closed(self) -> bool:
        return not self._fileobj or self._fileobj.closed

    def writable(self) -> bool:
        return self._fileobj.writable()

    def write(self, buffer) -> int:
        # TODO in python 3.12: buffer: collections.abc.Buffer
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        self._buf += buffer
        while len(self._buf) > DATA_CHUNK_SIZE:
            cyphertext = self._payload_chacha.encrypt(
                nonce=_nonce(counter=self._counter, last=False),
                data=self._buf[:DATA_CHUNK_SIZE],
                associated_data=b"",
            )
            writeall(self._fileobj, cyphertext)

            self._buf = self._buf[DATA_CHUNK_SIZE:]
            self._counter += 1

        # We always write everything we can and buffer the unencrypted bits
        return len(buffer)


def writeall(file: BinaryIO, data: bytes) -> int:
    written = 0
    while written < len(data):
        new_bytes = file.write(data[written:])
        if new_bytes is not None:
            written += new_bytes

    return written
