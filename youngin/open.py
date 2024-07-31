import io
from collections.abc import Iterable
from pathlib import Path
from typing import Literal

from youngin.identity import Identity, Recipient
from youngin.reader import AgeReader
from youngin.writer import AgeWriter


def open(
    file: io.IOBase | Path | str,
    mode: Literal["r", "w", "rt", "wt", "rb", "wb"] = "r",
    *,
    identities: Iterable[Identity] | None = None,
    recipients: Iterable[Recipient] | None = None,
) -> io.BufferedIOBase | io.TextIOBase:
    age_fp: io.BufferedIOBase | io.TextIOBase
    if "r" in mode:
        assert identities is not None, "no identites given"
        age_fp = AgeReader(file=file, identities=identities)
    elif "w" in mode:
        assert recipients is not None, "no recipients given"
        age_fp = AgeWriter(file=file, recipients=recipients)
    else:
        raise RuntimeError(f"invalid mode {mode}")

    if "b" not in mode:
        age_fp = io.TextIOWrapper(age_fp)

    return age_fp
