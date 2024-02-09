"""Age exceptions"""


class PayloadFailureException(Exception):
    """Raised if there was an error decrypting the payload."""


class HeaderFailureException(Exception):
    """Raised if there was an error parsing the header."""


class NoMatchException(Exception):
    """Raised if none of the provided identities could be matched to any of the
    recipients of an AgeWriter."""


class HmacFailureException(Exception):
    """Raised if the header HMAC did not match."""
