import io
import unittest
from collections.abc import Iterable
from pathlib import Path

import youngin
from youngin import AgeReader, Identity, ScryptPassphrase, X25519Identity


class TestkitTest(unittest.TestCase):
    def test_testkit(self) -> None:
        for testfile_path in Path("test/testkit").iterdir():
            self.subTest(testfile=testfile_path)
            expected_exception: type | None = None
            identities: list[Identity] = []
            armored = False

            with open(testfile_path, "rb") as testfile:
                while True:
                    line = next(testfile)
                    if line == b"\n":
                        break
                    key, value = line.split(b": ", maxsplit=1)
                    value = value[:-1]
                    match key:
                        case b"expect":
                            if value != b"success":
                                expected_error_name = value.decode()
                                exception_name = (
                                    "".join(
                                        word.capitalize()
                                        for word in expected_error_name.split()
                                    )
                                    + "Exception"
                                )
                                expected_exception = getattr(
                                    youngin, exception_name, Exception
                                )
                        case b"identity":
                            identities.append(
                                X25519Identity.from_secret_key(value.decode())
                            )
                        case b"passphrase":
                            identities.append(ScryptPassphrase(value))
                        case b"armored":
                            armored = value == b"yes"
                        case _:
                            assert ValueError(f"{line=}")

                file = io.BytesIO(testfile.read())

            run_testkit_test(
                self,
                file=file,
                identities=identities,
                armored=armored,
                expected_exception=expected_exception,
            )


def run_testkit_test(
    self: TestkitTest,
    file: io.IOBase,
    identities: Iterable[Identity],
    armored: bool,
    expected_exception: type[BaseException] | None,
) -> None:

    if armored:
        # raise unittest.SkipTest("armor not implemented yet")
        return

    chunks = []
    if expected_exception is not None:
        with self.assertRaises(expected_exception):
            agereader = AgeReader(file, identities=identities)
            while chunk := agereader.read():
                chunks.append(chunk)
    else:
        agereader = AgeReader(file, identities=identities)
        while chunk := agereader.read():
            chunks.append(chunk)


if __name__ == "__main__":
    unittest.main()
