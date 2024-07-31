"""Encrypt and decrypt files in the age format."""

from .exceptions import (
    HeaderFailureException,
    HmacFailureException,
    NoMatchException,
    PayloadFailureException,
)
from .identity import (
    Identity,
    Recipient,
    ScryptPassphrase,
    X25519Identity,
    X25519Recipient,
)
from .open import open
from .reader import AgeReader
from .writer import AgeWriter
