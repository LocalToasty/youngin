import io
import unittest

from youngin import AgeWriter, X25519Identity


class TestX25519IdentityFile(unittest.TestCase):

    def test_multiple_identities(self):
        identity_file = io.BytesIO(
            b"""AGE-SECRET-KEY-1FPNG2U7JFKLNKMZCMWG2RFQUFL6NT2LTACYL2QTRSGM9Z7ER9AWSJLG7R5\n"""
            b"""# a comment, also, the next key ends with \\r\\n\n"""
            b"""AGE-SECRET-KEY-1LQG9G7NNUXMLJADJFJN47N3YZ4LW7TVZ5H7YAQ7KSNKLHH2PQDSQLYCPGM\r\n"""
            b"""# and a final key\n"""
            b"""AGE-SECRET-KEY-1VPYTK3RPTRJ7RU0PCFT59Y37S0AF82AL03R5F0PSJV80LWUVPPMSP8YFVU"""
        )
        identities = list(X25519Identity.from_keyfile(identity_file))
        self.assertEqual(len(identities), 3)
        self.assertEqual(
            str(identities[0]),
            "AGE-SECRET-KEY-1FPNG2U7JFKLNKMZCMWG2RFQUFL6NT2LTACYL2QTRSGM9Z7ER9AWSJLG7R5",
        )
        self.assertEqual(
            str(identities[1]),
            "AGE-SECRET-KEY-1LQG9G7NNUXMLJADJFJN47N3YZ4LW7TVZ5H7YAQ7KSNKLHH2PQDSQLYCPGM",
        )
        self.assertEqual(
            str(identities[2]),
            "AGE-SECRET-KEY-1VPYTK3RPTRJ7RU0PCFT59Y37S0AF82AL03R5F0PSJV80LWUVPPMSP8YFVU",
        )

    def test_encrypted_identities(self):
        identitiy_str = (
            "AGE-SECRET-KEY-1FPNG2U7JFKLNKMZCMWG2RFQUFL6NT2LTACYL2QTRSGM9Z7ER9AWSJLG7R5"
        )
        encryption_identity = X25519Identity.generate()
        agefile = io.BytesIO()
        with AgeWriter(agefile, recipients=[encryption_identity.recipient()]) as writer:
            writer.write(identitiy_str.encode())

        agefile.seek(0)
        identities = list(
            X25519Identity.from_keyfile(agefile, identities=[encryption_identity])
        )
        self.assertEqual(len(identities), 1)
        self.assertEqual(str(identities[0]), identitiy_str)


if __name__ == "__main__":
    unittest.main()
