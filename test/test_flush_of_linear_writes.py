import io
import os
import unittest

from youngin import AgeWriter, X25519Identity
from youngin.reader import DATA_CHUNK_SIZE


class TestWriter(unittest.TestCase):

    def test_flush_of_linear_writes(self):
        identity = X25519Identity.from_secret_key(
            "AGE-SECRET-KEY-1SQ6CPMFJY75DWTW5RECWYWV0AE9J7T67HX2JV6X8WVY8ZLHZC3CSWDKJSF"
        )
        agefile = io.BytesIO()
        with AgeWriter(agefile, recipients=[identity.recipient()]) as writer:
            chunks_to_write = 3
            writer.write(b"0" * (DATA_CHUNK_SIZE * chunks_to_write))
            self.assertLess(len(writer._payload._chunks), chunks_to_write)


if __name__ == "__main__":
    unittest.main()
