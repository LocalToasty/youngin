"""Write age-encrypted files"""
import io
import os
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .binascii import b64encode_no_pad
from .identity import Recipient, ScryptPassphrase
from .reader import DATA_CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE, TAG_SIZE, FileKey


class AgeWriter(io.BufferedIOBase):
    """A binary stream transparently encrypting data before writing it to disk.

    No data written to this stream will be written to the underlying raw stream
    unencrypted.  Due to the requirement of age to not reuse a payload key,
    seeking to and overwriting already-written data is not possible.
    """

    def __init__(
        self,
        file: io.BufferedIOBase | Path | str,
        *,
        recipients: Iterable[Recipient],
    ) -> None:
        # pylint: disable=consider-using-with
        if isinstance(file, (Path, str)):
            file = open(file, "wb")
        assert isinstance(file, io.BufferedIOBase)

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

        writeall(file, header_bytes)
        writeall(file, b" " + b64encode_no_pad(digest) + b"\n")
        writeall(file, payload_nonce)

        self._chacha_file = ChaChaFile(
            file,
            chunk_size=DATA_CHUNK_SIZE,
            chacha=ChaCha20Poly1305(payload_key),
        )

    def close(self) -> None:
        if self.closed:
            return None

        return self._chacha_file.close()

    @property
    def closed(self) -> bool:
        """True if the underlying fileobject is closed"""
        return not self._chacha_file or self._chacha_file.closed

    def writable(self) -> bool:
        return self._chacha_file.writable()

    def write(self, buffer) -> int:
        # TODO in python 3.12: buffer: collections.abc.Buffer
        if self.closed:
            raise ValueError("I/O operation on closed file.")

        return self._chacha_file.write(buffer)


class ChaChaFile(io.BufferedIOBase):
    def __init__(
        self, file: io.RawIOBase, chunk_size: int, chacha: ChaCha20Poly1305
    ) -> None:
        self._fileobj = file
        if self._fileobj.seekable():
            self._raw_offset = self._fileobj.seek(0, os.SEEK_CUR)

        self._chacha = chacha

        self._chunk_size = chunk_size
        self._chunks_committed_so_far = 0
        self._chunks: list[Chunk | None] = [Chunk(self._chunk_size)]
        self._pos = 0
        self._size = 0

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        match whence:
            case os.SEEK_SET:
                new_pos = offset
            case os.SEEK_CUR:
                new_pos = self._pos + offset
            case os.SEEK_END:
                new_pos = min(self._size + offset, 0)

        self._pos = new_pos

        while (
            len(self._chunks) + self._chunks_committed_so_far
        ) * self._chunk_size < self._pos:
            self._chunks.append(Chunk(self._chunk_size))

        self._size = max(self._size, self._pos)

        return self._pos

    def close(self) -> None:
        if self.closed:
            return
        if self._fileobj.seekable():
            # Rewind to first unwritten chunk
            self._fileobj.seek(
                self._raw_offset
                + (self._chunk_size + TAG_SIZE) * self._chunks_committed_so_far,
                os.SEEK_SET,
            )

        for i, chunk in enumerate(self._chunks[:-1]):
            if chunk is None:
                assert self._fileobj.seekable()
                self.seek(ENCRYPTED_CHUNK_SIZE, os.SEEK_CUR)
            else:
                writeall(
                    self._fileobj,
                    self._chacha.encrypt(
                        nonce=_nonce(self._chunks_committed_so_far + i, last=False),
                        data=bytes(chunk),
                        associated_data=b"",
                    ),
                )

        assert self._chunks[-1] is not None
        writeall(
            self._fileobj,
            self._chacha.encrypt(
                nonce=_nonce(
                    self._chunks_committed_so_far + len(self._chunks) - 1, last=True
                ),
                data=bytes(self._chunks[-1])[: self._size % self._chunk_size],
                associated_data=b"",
            ),
        )

        self._fileobj.close()

    @property
    def closed(self) -> bool:
        return self._fileobj.closed

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def write(self, buffer) -> int:
        """Write all of data to a stream, blocking until done."""
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        written = 0
        while written < len(buffer):
            new_bytes = self.write1(buffer[written:])
            if new_bytes is not None:
                written += new_bytes

        return written

    def write1(self, buffer) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if self._pos // self._chunk_size < self._chunks_committed_so_far:
            raise io.UnsupportedOperation("cannot seek to already committed chunk")

        pos_in_chunk = self._pos % self._chunk_size
        space_left_in_chunk = self._chunk_size - pos_in_chunk

        buffer = buffer[:space_left_in_chunk]
        current_chunk = self._chunks[
            self._pos // self._chunk_size - self._chunks_committed_so_far
        ]
        assert current_chunk is not None
        current_chunk.write(pos_in_chunk, data=buffer)

        if current_chunk.full and len(self._chunks) > 1:
            if self._pos // self._chunk_size == 0:
                writeall(
                    self._fileobj,
                    self._chacha.encrypt(
                        nonce=_nonce(self._chunks_committed_so_far, last=False),
                        data=bytes(current_chunk),
                        associated_data=b"",
                    ),
                )
                self._chunks = self._chunks[1:]
                self._chunks_committed_so_far += 1

            elif (
                self._fileobj.seekable()
                and (self._pos // self._chunk_size)
                < self._chunks_committed_so_far + len(self._chunks) - 1
            ):
                assert isinstance(self._raw_offset, int)
                self._fileobj.seek(
                    (self._pos // self._chunk_size) * (self._chunk_size + TAG_SIZE)
                    + self._raw_offset,
                    os.SEEK_SET,
                )
                writeall(
                    self._fileobj,
                    self._chacha.encrypt(
                        nonce=_nonce(self._chunks_committed_so_far, last=False),
                        data=bytes(current_chunk),
                        associated_data=b"",
                    ),
                )
                self._chunks[
                    self._pos // self._chunk_size - self._chunks_committed_so_far
                ] = None

        if len(buffer) == space_left_in_chunk:
            self._chunks.append(Chunk(self._chunk_size))
        self._pos += len(buffer)
        self._size = max(self._size, self._pos)

        return len(buffer)

    def writable(self) -> bool:
        return self._fileobj.writable()


def _nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\1" if last else b"\0")


def writeall(stream: io.RawIOBase, data: bytes) -> int:
    """Write all of data to a stream, blocking until done."""
    written = 0
    while written < len(data):
        new_bytes = stream.write(data[written:])
        if new_bytes is not None:
            written += new_bytes

    return written


class Chunk:
    """A chunk is a series of extents which add up to a fixed size"""

    def __init__(self, size: int) -> None:
        self._extents: list[Data | Zeros] = [Zeros(size)]
        """Extents making up this chunk.
        
        It has to maintain the following invariants:
          1. The sum of the extents' lenghts has to be `size`.
          2. No two consecutive chunks may be of the same type.
        """

    def write(self, start: int, data: bytes) -> None:
        pos = 0
        for extent_i, extent in enumerate(self._extents):
            if pos + len(extent) > start:
                # We have found our extent!
                if not isinstance(extent, Zeros) or len(extent) < len(data):
                    raise RuntimeError("can't overwrite already written data")
                break
            else:
                pos += len(extent)
        else:
            raise RuntimeError("unreachable")

        # Create a new data extent
        continuous_data_chunks = [data]
        if pos == start:
            if extent_i > 0 and isinstance(
                previous_extent := self._extents[extent_i - 1], Data
            ):
                # The newly written data continues after the previous extent, so merge them
                extents_before = self._extents[: extent_i - 1]
                continuous_data_chunks.insert(0, previous_extent.data)
            else:
                extents_before = self._extents[:extent_i]
        else:
            extents_before = [*self._extents[:extent_i], Zeros(start - pos)]

        if start + len(data) == pos + len(extent):
            if extent_i < len(self._extents) - 1 and isinstance(
                next_extent := self._extents[extent_i + 1], Data
            ):
                # There's data immediately after this data chunk, so merge them
                extents_after = self._extents[extent_i + 2 :]
                continuous_data_chunks.append(next_extent.data)
            else:
                extents_after = self._extents[extent_i + 1 :]
        else:
            extents_after = [
                Zeros(len(extent) - len(data) - (start - pos)),
                *self._extents[extent_i + 1 :],
            ]

        self._extents = [
            *extents_before,
            Data(b"".join(continuous_data_chunks)),
            *extents_after,
        ]

    @property
    def empty(self) -> bool:
        return (len(self._extents) == 1) and isinstance(self._extents[0], Zeros)

    @property
    def full(self) -> bool:
        """True if the entire block has been written to"""
        return (len(self._extents) == 1) and isinstance(self._extents[0], Data)

    def __bytes__(self) -> bytes:
        return b"".join(bytes(extent) for extent in self._extents)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {', '.join(repr(e) for e in self._extents)}>"


@dataclass
class Data:
    data: bytes

    def __len__(self) -> int:
        return len(self.data)

    def __bytes__(self) -> bytes:
        return self.data

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.data!r}>"


@dataclass
class Zeros:
    size: int

    def __len__(self):
        return self.size

    def __bytes__(self) -> bytes:
        return bytes(self.size)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} x{self.size}>"
