import io
import tempfile
import unittest

from youngin import AgeReader, AgeWriter, X25519Identity


class TestWriterClose(unittest.TestCase):

    def test_writer_close_on_fileobj(self):
        identity = X25519Identity.from_secret_key(
            "AGE-SECRET-KEY-1SQ6CPMFJY75DWTW5RECWYWV0AE9J7T67HX2JV6X8WVY8ZLHZC3CSWDKJSF"
        )
        raw = io.BytesIO()
        with AgeWriter(raw, recipients=[identity.recipient()]) as writer:
            pass

        self.assertTrue(writer.closed)
        self.assertFalse(raw.closed)

    def test_writer_close_with_filename(self):
        identity = X25519Identity.from_secret_key(
            "AGE-SECRET-KEY-1SQ6CPMFJY75DWTW5RECWYWV0AE9J7T67HX2JV6X8WVY8ZLHZC3CSWDKJSF"
        )
        with tempfile.NamedTemporaryFile() as tmpfile:
            with AgeWriter(tmpfile.name, recipients=[identity.recipient()]) as writer:
                pass

            self.assertTrue(writer.closed)
            self.assertIsNone(writer._payload._fileobj)


class TestReaderClose(unittest.TestCase):

    def test_writer_close_on_fileobj(self):
        identity = X25519Identity.from_secret_key(
            "AGE-SECRET-KEY-1SQ6CPMFJY75DWTW5RECWYWV0AE9J7T67HX2JV6X8WVY8ZLHZC3CSWDKJSF"
        )
        raw = io.BytesIO()
        with AgeWriter(raw, recipients=[identity.recipient()]):
            pass
        raw.seek(0)

        with AgeReader(raw, identities=[identity]) as reader:
            pass

        self.assertTrue(reader.closed)
        self.assertFalse(raw.closed)

    def test_writer_close_with_filename(self):
        identity = X25519Identity.from_secret_key(
            "AGE-SECRET-KEY-1SQ6CPMFJY75DWTW5RECWYWV0AE9J7T67HX2JV6X8WVY8ZLHZC3CSWDKJSF"
        )
        with tempfile.NamedTemporaryFile() as tmpfile:
            with AgeWriter(tmpfile.name, recipients=[identity.recipient()]):
                pass

            with AgeReader(tmpfile.name, identities=[identity]) as reader:
                pass

            self.assertTrue(reader.closed)
            self.assertIsNone(reader._fileobj)


if __name__ == "__main__":
    unittest.main()
