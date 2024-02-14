"""Native identity and recipient implementations for age"""

import base64
import io
import re
import secrets
from abc import ABC, abstractmethod
from collections.abc import Iterable
from getpass import getpass
from pathlib import Path
from typing import Literal, NewType, Optional, Self, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .binascii import b64decode_no_pad, b64encode_no_pad, bech32_decode, bech32_encode
from .exceptions import HeaderFailureException

__all__ = [
    "Identity",
    "Recipient",
    "X25519Identity",
    "X25519Recipient",
    "ScryptPassphrase",
]

MAX_WORK_FACTOR_LOG_2 = 20


class Stanza:
    # pylint: disable=too-few-public-methods
    """A stanza in an age header"""

    def __init__(self, args: Sequence[bytes], body: bytes) -> None:
        if not args:
            raise HeaderFailureException("empty stanza is not allowed")
        if not all(args):
            raise HeaderFailureException("empty stanza argument")
        try:
            [arg.decode(encoding="ascii") for arg in args]
        except UnicodeDecodeError as e:
            raise HeaderFailureException("stanza args have to be all ascii") from e
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


class Recipient(ABC):
    """A recipient of an age-encrypted file"""

    # pylint: disable=too-few-public-methods
    @abstractmethod
    def stanza(self, file_key: FileKey) -> Stanza:
        """Returns a stanza describing this recipient."""


class Identity(ABC):
    """The identity of a person an age message is addressed to"""

    # pylint: disable=too-few-public-methods
    @abstractmethod
    def decode(self, stanza: Stanza) -> Optional[FileKey]:
        """Extract the file key from a stanza.

        Returns `None` if the stanza's recipient does not match this identity.
        """

    @abstractmethod
    def recipient(self) -> Recipient:
        """Generate a recipient from this identity

        In some cases (like for example Scrypt identities) the recipient may
        contain SENSITIVE INFORMATION and may not be freely shared.
        """


class X25519Recipient(Recipient):
    """A X25519 recipient for an age file"""

    def __init__(self, recipient: X25519PublicKey) -> None:
        self._recipient = recipient

    @classmethod
    def from_public_key(cls, age_recipient: str) -> Self:
        """Create an age X25519 recipient from an age public key."""
        return cls(
            X25519PublicKey.from_public_bytes(bech32_decode("age", age_recipient))
        )

    @classmethod
    def from_recipient_file(
        cls, recipient_file: io.IOBase | Path | str
    ) -> Iterable[Self]:
        """Read X25519 recipients from a recipient file.

        Each line in the recipient file has to contain an X25519 recipient
        public key.  Empty lines and lines starting with `#` are ignored.
        """
        if isinstance(recipient_file, (Path, str)):
            recipient_file = open(recipient_file, "rb")

        return [
            cls.from_public_key(line.strip().decode())
            for line in recipient_file
            if not line.startswith(b"#") and line.strip()
        ]

    def __str__(self) -> str:
        return bech32_encode("age", self._recipient.public_bytes_raw())

    def __repr__(self) -> str:
        return f"<X25519Recipient {self}>"

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


class X25519Identity(Identity):
    def __init__(self, identity: X25519PrivateKey) -> None:
        self._identity = identity

    @classmethod
    def generate(cls) -> Self:
        """Create a new X25519 identity."""
        return cls(X25519PrivateKey.generate())

    @classmethod
    def from_secret_key(cls, age_secret_key: str) -> Self:
        identity = bech32_decode("age-secret-key-", age_secret_key)
        return cls(X25519PrivateKey.from_private_bytes(identity))

    @classmethod
    def from_keyfile(
        cls,
        file: io.IOBase | Path | str,
        identities: Iterable[Identity] | Literal["interactive"] | None = None,
    ) -> Iterable[Self]:
        """Read one or multiple X25519 identities from a file.

        Args:
            file:  File object to read the keys from.  Has to be seekable.
            identities:  A list of identities used to decrypt the keyfile in
                case it is encrypted.  If "interactive" is specified, the user
                is prompted for a passphrase if and only if the keyfile is
                encrypted.

        Returns:
            An iterable of identities stored in the keyfile.
        """
        if isinstance(file, (Path, str)):
            file = open(file, "rb")

        magic = file.read(len(b"age-encryption.org/v1"))
        file.seek(0)  # TODO make seek-less
        keyfile: io.IOBase
        if magic == b"age-encryption.org/v1":
            if identities == "interactive":
                passphrase = getpass("Enter passphrase for key: ")
                identities = [ScryptPassphrase(passphrase.encode())]
            if not identities:
                raise RuntimeError("no age key to decrypt keyfile supplied")
            from .reader import AgeReader

            keyfile = AgeReader(file, identities)
        else:
            keyfile = file

        return [
            cls.from_secret_key(line.strip().decode())
            for line in keyfile
            if not line.startswith(b"#") and line.strip()
        ]

    def recipient(self) -> X25519Recipient:
        return X25519Recipient(self._identity.public_key())

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

    def __str__(self) -> str:
        return bech32_encode(
            "age-secret-key-", self._identity.private_bytes_raw()
        ).upper()


class ScryptPassphrase(Recipient, Identity):
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

    def recipient(self) -> Self:
        return self
