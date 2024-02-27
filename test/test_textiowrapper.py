import io
import unittest

from youngin import AgeReader, AgeWriter, X25519Identity


class TestTextIOWrapper(unittest.TestCase):

    def test_text_io_wrapper(self):
        identity = X25519Identity.from_secret_key(
            "AGE-SECRET-KEY-1SQ6CPMFJY75DWTW5RECWYWV0AE9J7T67HX2JV6X8WVY8ZLHZC3CSWDKJSF"
        )
        agefile = io.BytesIO()
        with AgeWriter(agefile, recipients=[identity.recipient()]) as writer:
            with io.TextIOWrapper(writer) as textwriter:  # type: ignore[reportArgumentType]
                textwriter.write("Hello, world")

        agefile.seek(0)

        with AgeReader(agefile, identities=[identity]) as reader:
            with io.TextIOWrapper(reader) as textreader:  # type: ignore[reportArgumentType]
                decrypted = textreader.read()

        self.assertEqual(decrypted, "Hello, world")


if __name__ == "__main__":
    unittest.main()
