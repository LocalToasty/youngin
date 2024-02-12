import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory, TemporaryFile

from youngin import AgeReader, AgeWriter, X25519Identity


class TestWriter(unittest.TestCase):

    def test_writing_with_holes(self):
        identity = X25519Identity.from_secret_key(
            "AGE-SECRET-KEY-1SQ6CPMFJY75DWTW5RECWYWV0AE9J7T67HX2JV6X8WVY8ZLHZC3CSWDKJSF"
        )
        with TemporaryDirectory() as tempdir:
            with AgeWriter(
                Path(tempdir) / "agefile", recipients=[identity.recipient()]
            ) as writer:
                pos = writer.seek(3)
                self.assertEqual(pos, 3)

                writer.write(b"hello")
                pos = writer.seek(10, os.SEEK_CUR)
                self.assertEqual(pos, 3 + len(b"hello") + 10)

                pos = writer.seek(-8, os.SEEK_END)
                self.assertEqual(pos, 3 + len(b"hello") + 10 - 8)
                writer.write(b"world")

            with AgeReader(Path(tempdir) / "agefile", identities=[identity]) as reader:
                decrypted = reader.read()

        self.assertEqual(decrypted, b"\0\0\0hello\0\0world\0\0\0")

    def test_overwriting(self):
        identity = X25519Identity.from_secret_key(
            "AGE-SECRET-KEY-1SQ6CPMFJY75DWTW5RECWYWV0AE9J7T67HX2JV6X8WVY8ZLHZC3CSWDKJSF"
        )
        with TemporaryFile() as tempfile:
            with AgeWriter(tempfile, recipients=[identity.recipient()]) as writer:
                writer.write(b"Hello, my name is Alice")
                writer.seek(-(len("Alice")))
                with self.assertRaises(RuntimeError):
                    writer.write(b"Victor")


if __name__ == "__main__":
    unittest.main()
