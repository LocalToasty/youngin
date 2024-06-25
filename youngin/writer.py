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
        file: io.IOBase | Path | str,
        *,
        recipients: Iterable[Recipient],
    ) -> None:
        if isinstance(file, (Path, str)):
            self._stream_passed = False
            """False if the underlying stream was not passed as a file object,
            but as a path"""
            # pylint: disable=consider-using-with
            file = open(file, "wb")
        else:
            self._stream_passed = True

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

        # pylint: disable=duplicate-code
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

        self._payload = AgePayload(
            file,
            chacha=ChaCha20Poly1305(payload_key),
        )

    def close(self) -> None:
        if self.closed:
            return

        if self._stream_passed:
            self._payload.detach()
        else:
            self._payload.close()

    @property
    def closed(self) -> bool:
        """True if the underlying fileobject is closed"""
        return self._payload.closed

    def detach(self) -> io.RawIOBase:
        # TODO Technically not type-correct
        return self._detach()  # type: ignore[return-value]

    def _detach(self) -> io.IOBase:
        raw = self._payload.detach()
        return raw

    def writable(self) -> bool:
        return self._payload.writable()

    def write(self, buffer) -> int:
        # TODO in python 3.12: buffer: collections.abc.Buffer
        if self.closed:
            raise ValueError("I/O operation on closed or detached file.")

        return self._payload.write(buffer)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return self._payload.seek(offset, whence)


class AgePayload(io.BufferedIOBase):
    """Helper class for writing age files.

    Since we may not reuse nonces, we have to data until a full chunk (64KiB)
    has been written.  This class waits for chunks to be completely written
    before writing them into the underlying stream.  If the underlying stream is
    not seekable, it furthermore buffers complete chunks until all previous
    chunks have been written.
    """

    def __init__(self, file: io.IOBase, chacha: ChaCha20Poly1305) -> None:

        # `None` because `detach()` unsets `_fileobj``
        self._fileobj: io.IOBase | None = file
        if self._fileobj.seekable():
            self._raw_offset = self._fileobj.seek(0, os.SEEK_CUR)
        else:
            self._raw_offset = None

        self._chacha = chacha

        self._chunks_committed_so_far = 0
        # The chunks of the file starting from the `_chunks_commited_so_far`th one.
        self._chunks: list[Chunk] = [Chunk(DATA_CHUNK_SIZE)]

        # The current position in the file,
        # i.e. where stuff will be written to next
        self._pos = 0

        # The maximum size of the file,
        # i.e. the furthest position reached by seeks or writes so far
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
                new_pos = max(self._size + offset, 0)
            case _:
                raise NotImplementedError(
                    "Only SEEK_SET, SEEK_CUR and SEEK_END are implemented for AgeWriter"
                )

        self._pos = new_pos

        while (
            len(self._chunks) + self._chunks_committed_so_far
        ) * DATA_CHUNK_SIZE < self._pos:
            self._chunks.append(Chunk(DATA_CHUNK_SIZE))

        self._size = max(self._size, self._pos)

        return self._pos

    def close(self) -> None:
        if self.closed:
            return
        assert self._fileobj

        fileobj = self._detach()
        fileobj.close()

    @property
    def closed(self) -> bool:
        """Returns true if file has been closed."""
        return self._fileobj is None or self._fileobj.closed

    def detach(self) -> io.RawIOBase:
        # TODO Technically not type-correct
        # because the underlying stream can be a non-raw one
        return self._detach()  # type: ignore[return-value]

    def _detach(self) -> io.IOBase:
        """Flushes all data not-yet-written to underyling stream and returns it"""

        if self.closed or not self._fileobj:
            raise ValueError("I/O operation on closed or detached file.")
        if self._fileobj.seekable():
            # Rewind to first unwritten chunk
            assert (
                self._raw_offset is not None
            ), "`_raw_offset` should have been set in the constructor if the underlying stream is seekable"
            self._fileobj.seek(
                self._raw_offset
                + (DATA_CHUNK_SIZE + TAG_SIZE) * self._chunks_committed_so_far,
                os.SEEK_SET,
            )

        for i, chunk in enumerate(self._chunks[:-1]):
            writeall(
                self._fileobj,
                self._chacha.encrypt(
                    nonce=_nonce(self._chunks_committed_so_far + i, last=False),
                    data=bytes(chunk),
                    associated_data=b"",
                ),
            )

        writeall(
            self._fileobj,
            self._chacha.encrypt(
                nonce=_nonce(
                    self._chunks_committed_so_far + len(self._chunks) - 1, last=True
                ),
                data=bytes(self._chunks[-1])[: self._size % DATA_CHUNK_SIZE],
                associated_data=b"",
            ),
        )

        raw = self._fileobj
        self._fileobj = None
        return raw

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
        """Writes buffer while calling write of the underlying stream at most once.

        Returns:
            The number of bytes written.
        """
        if self.closed or not self._fileobj:
            raise ValueError("I/O operation on closed or detached file.")

        if self._pos // DATA_CHUNK_SIZE < self._chunks_committed_so_far:
            # The chunk is already commited, i.e. has already been written to
            raise RuntimeError("cannot overwrite already written data")

        pos_in_chunk = self._pos % DATA_CHUNK_SIZE
        space_left_in_chunk = DATA_CHUNK_SIZE - pos_in_chunk

        buffer = buffer[:space_left_in_chunk]
        current_chunk = self._chunks[
            self._pos // DATA_CHUNK_SIZE - self._chunks_committed_so_far
        ]
        current_chunk.write(pos_in_chunk, data=buffer)

        self._commit_fully_written_chunks()

        if len(buffer) == space_left_in_chunk:
            # We've reached the end of this chunk,
            # time to append a new one!
            self._chunks.append(Chunk(DATA_CHUNK_SIZE))
        self._pos += len(buffer)
        self._size = max(self._size, self._pos)

        return len(buffer)

    def _commit_fully_written_chunks(self) -> None:
        """Commits all already fully written chunks from on the left end of the file"""

        assert (
            self._fileobj != None
        ), "the caller must ensure that the stream has not been detached"

        while len(self._chunks) > 1:
            chunk = self._chunks[0]
            if chunk.full:
                writeall(
                    self._fileobj,
                    self._chacha.encrypt(
                        nonce=_nonce(self._chunks_committed_so_far, last=False),
                        data=bytes(chunk),
                        associated_data=b"",
                    ),
                )
                self._chunks_committed_so_far += 1
                self._chunks = self._chunks[1:]
            else:
                # We've encountered the first none-full chunk, so let's stop for now
                break

    def writable(self) -> bool:
        return self._fileobj is not None and self._fileobj.writable()


def _nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\1" if last else b"\0")


def writeall(stream: io.IOBase, data: bytes) -> int:
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
          1. The sum of the extents' lengths has to be `size`.
          2. No two consecutive chunks may be of the same type.
        """

    def write(self, start: int, data: bytes) -> None:
        """Writes data to this chunk.

        Args:
            start:  position in the chunk to write the data to
            data:  data to write

        Already written data may not be written to again.  Furthermore the data
        has to fit into the remainder of the chunk.
        """
        pos = 0
        for extent_i, extent in enumerate(self._extents):
            if pos + len(extent) > start:
                # We have found our extent!
                if not isinstance(extent, Zeros) or len(extent) < len(data):
                    raise RuntimeError("can't overwrite already written data")
                break

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
        """Turns true if this chunk has not yet been written to"""
        return (len(self._extents) == 1) and isinstance(self._extents[0], Zeros)

    @property
    def full(self) -> bool:
        """True if the entire block has been written to
        (and may thus be written to the underlying stream)"""
        return (len(self._extents) == 1) and isinstance(self._extents[0], Data)

    def __bytes__(self) -> bytes:
        return b"".join(bytes(extent) for extent in self._extents)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {', '.join(repr(e) for e in self._extents)}>"


@dataclass
class Data:
    """An extent containing data (which may thus not be overwritten)"""

    data: bytes

    def __len__(self) -> int:
        return len(self.data)

    def __bytes__(self) -> bytes:
        return self.data

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.data!r}>"


@dataclass
class Zeros:
    """An as-of-yet not written to extent (assumed to be all zeroes)"""

    size: int

    def __len__(self):
        return self.size

    def __bytes__(self) -> bytes:
        return bytes(self.size)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} x{self.size}>"
