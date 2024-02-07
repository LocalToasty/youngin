# %%
import io
import unittest
from pathlib import Path

import pyage
from pyage import AgeReader, ScryptPassphrase, X25519Identity


class AgeTestCase(unittest.TestCase):
    def __init__(self, testfile_path: Path) -> None:
        self.expected_exception = None
        self.identities = []
        self.armored = False

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
                            self.expected_exception = getattr(
                                pyage, exception_name, Exception
                            )
                    case b"identity":
                        self.identities.append(
                            X25519Identity.from_secret_key(value.decode())
                        )
                    case b"passphrase":
                        self.identities.append(ScryptPassphrase(value))
                    case b"armored":
                        self.armored = value == b"yes"
                    case _:
                        assert ValueError(f"{line=}")

            self.file = io.BytesIO(testfile.read())

            setattr(self, testfile_path.name, self.test)
            super().__init__(testfile_path.name)

    def test(self):
        if self.armored:
            raise unittest.SkipTest("armor not implemented yet")

        chunks = []
        if self.expected_exception:
            with self.assertRaises(self.expected_exception):
                agereader = AgeReader(self.file, identities=self.identities)
                while chunk := agereader.read():
                    chunks.append(chunk)
        else:
            agereader = AgeReader(self.file, identities=self.identities)
            while chunk := agereader.read():
                chunks.append(chunk)


if __name__ == "__main__":
    suite = unittest.TestSuite()
    for testfile_path in list(Path("testkit").iterdir()):
        suite.addTest(AgeTestCase(testfile_path))
    runner = unittest.TextTestRunner()
    runner.run(suite)
