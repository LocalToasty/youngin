import io
import os
import unittest

from youngin import AgeReader, AgeWriter, X25519Identity


class TestReader(unittest.TestCase):

    def test_seek(self):
        identity = X25519Identity.from_secret_key(
            "AGE-SECRET-KEY-1SQ6CPMFJY75DWTW5RECWYWV0AE9J7T67HX2JV6X8WVY8ZLHZC3CSWDKJSF"
        )
        agefile = io.BytesIO()
        with AgeWriter(agefile, recipients=[identity.recipient()]) as writer:
            writer.write(b"Hello, beautiful world!")
            writer.detach()

        agefile.seek(0)
        with AgeReader(agefile, identities=[identity]) as reader:
            decrypted = reader.read(5)
            self.assertEqual(decrypted, b"Hello")

            pos = reader.seek(len("Hello, beautiful "), os.SEEK_SET)
            self.assertEqual(pos, len(b"Hello, beautiful "))

            decrypted = reader.read(5)
            self.assertEqual(decrypted, b"world")

            pos = reader.seek(-len("world!"), os.SEEK_END)
            self.assertEqual(pos, len(b"Hello, beautiful "))


if __name__ == "__main__":
    unittest.main()
