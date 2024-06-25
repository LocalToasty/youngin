import io
import os
import unittest

from youngin import AgeReader, AgeWriter, X25519Identity
from youngin.reader import DATA_CHUNK_SIZE


class TestReader(unittest.TestCase):

    def test_seek(self):
        identity = X25519Identity.from_secret_key(
            "AGE-SECRET-KEY-1SQ6CPMFJY75DWTW5RECWYWV0AE9J7T67HX2JV6X8WVY8ZLHZC3CSWDKJSF"
        )
        agefile = io.BytesIO()
        with AgeWriter(agefile, recipients=[identity.recipient()]) as writer:
            writer.write(b"Hello, beautiful world!")

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

    def test_long_seek(self):
        identity = X25519Identity.from_secret_key(
            "AGE-SECRET-KEY-1SQ6CPMFJY75DWTW5RECWYWV0AE9J7T67HX2JV6X8WVY8ZLHZC3CSWDKJSF"
        )
        agefile = io.BytesIO()
        with AgeWriter(agefile, recipients=[identity.recipient()]) as writer:
            for _ in range(DATA_CHUNK_SIZE):  # roughly three chunks
                writer.write(b"abc")

        agefile.seek(0)
        with AgeReader(agefile, identities=[identity]) as reader:
            # seek to somewhere in the second chunk
            target_pos = DATA_CHUNK_SIZE + DATA_CHUNK_SIZE // 2
            pos = reader.seek(target_pos)
            self.assertEqual(pos, target_pos)

            decrypted = reader.read(3)
            self.assertEqual(decrypted, b"abcab"[target_pos % 3 :][:3])

            # seek back to position before this
            target_pos = DATA_CHUNK_SIZE // 2
            pos = reader.seek(target_pos)
            self.assertEqual(pos, target_pos)

            decrypted = reader.read(3)
            self.assertEqual(decrypted, b"abcab"[target_pos % 3 :][:3])


if __name__ == "__main__":
    unittest.main()
