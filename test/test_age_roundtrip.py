import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from youngin import AgeReader, AgeWriter, ScryptPassphrase, X25519Identity


class TestAgeRoundtrip(unittest.TestCase):

    def test_x25519_roundtrip(self):
        identity = X25519Identity.from_secret_key(
            "AGE-SECRET-KEY-1SQ6CPMFJY75DWTW5RECWYWV0AE9J7T67HX2JV6X8WVY8ZLHZC3CSWDKJSF"
        )
        message = b"I'm a little teapot"
        with TemporaryDirectory() as tempdir:
            with AgeWriter(
                Path(tempdir) / "agefile", recipients=[identity.recipient()]
            ) as writer:
                writer.write(message)

            with AgeReader(Path(tempdir) / "agefile", identities=[identity]) as reader:
                decrypted = reader.read()

        self.assertEqual(message, decrypted)

    def test_scrypt_roundtrip(self):
        identity = ScryptPassphrase(b"correct-horse-battery-staple")
        message = b"I'm a little teapot"
        with TemporaryDirectory() as tempdir:
            with AgeWriter(
                Path(tempdir) / "agefile", recipients=[identity.recipient()]
            ) as writer:
                writer.write(message)

            with AgeReader(Path(tempdir) / "agefile", identities=[identity]) as reader:
                decrypted = reader.read()

        self.assertEqual(message, decrypted)


if __name__ == "__main__":
    unittest.main()
