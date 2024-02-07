#!/usr/bin/env python3
import os
import sys
from argparse import ArgumentParser, FileType
from datetime import datetime
from functools import partial
from getpass import getpass

from . import (
    AgeReader,
    AgeWriter,
    Identity,
    ScryptPassphrase,
    X25519Identity,
    X25519Recipient,
)
from .age import DATA_CHUNK_SIZE, writeall


def main() -> None:
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen_parser = subparsers.add_parser("keygen")
    keygen_parser.add_argument(
        "-o",
        "--output",
        default="-",
    )

    encrypt_parser = subparsers.add_parser("encrypt")
    encrypt_parser.add_argument(
        "-o",
        "--output",
        dest="outfile",
        type=FileType("wb"),
        default=sys.stdout.buffer,
    )
    encrypt_parser.add_argument(
        "-r",
        "--recipient",
        metavar="RECIPIENT",
        dest="recipients",
        type=X25519Recipient.from_public_key,
        default=None,
        action="append",
    )
    encrypt_parser.add_argument(
        "infile",
        metavar="INPUT",
        type=FileType("rb"),
        default=sys.stdin.buffer,
        nargs="?",
    )

    decrypt_parser = subparsers.add_parser("decrypt")
    decrypt_parser.add_argument(
        "-o",
        "--output",
        dest="outfile",
        type=FileType("wb"),
        default=sys.stdout.buffer,
    )
    decrypt_parser.add_argument(
        "-i",
        "--identity",
        default=None,
        metavar="IDENTITYFILE",
        dest="identities",
        action="append",
    )
    decrypt_parser.add_argument(
        "infile",
        metavar="INPUT",
        type=FileType("rb"),
        default=sys.stdin.buffer,
        nargs="?",
    )

    args = parser.parse_args()

    match args.command:
        case "keygen":
            identity = X25519Identity.generate()
            recipient = identity.recipient()
            if args.output == "-":
                outfile = sys.stdout
            else:
                outfile = open(args.output, "w", opener=partial(os.open, mode=0o600))

            outfile.write(f"# created: {datetime.now().astimezone().isoformat()}\n")
            outfile.write(f"# public key: {recipient}\n")
            outfile.write(f"{identity}\n")

            if not outfile.isatty():
                sys.stderr.write(f"Public key: {recipient}\n")

        case "encrypt":
            if args.recipients:
                recipients = args.recipients
            else:
                # Ask for passphrase
                passphrase = getpass("Enter passphrase: ")
                if passphrase != getpass("Confirm passphrase: "):
                    raise RuntimeError("passphrases didn't match")
                recipients = [ScryptPassphrase(passphrase=passphrase.encode())]

            with AgeWriter(args.outfile, recipients=recipients) as agewriter:
                while chunk := args.infile.read(DATA_CHUNK_SIZE):
                    agewriter.write(chunk)

        case "decrypt":
            identities: list[Identity] = []
            # Gather identities, either from one of the key files or as a provided
            # if none is provided
            if args.identities:
                for identity_file_path in args.identities:
                    with open(identity_file_path, "rb") as identity_file:
                        magic = identity_file.peek(len(b"age-encryption.org/v1\n"))
                        if magic.startswith(b"age-encryption.org/v1\n"):
                            passphrase = getpass(
                                f"Enter passphrase for {identity_file_path}: "
                            )
                            identities += X25519Identity.from_keyfile(
                                identity_file,
                                identities=[ScryptPassphrase(passphrase.encode())],
                            )
                        else:
                            identities += X25519Identity.from_keyfile(identity_file)
            else:
                identities = [ScryptPassphrase(getpass(f"Enter passphrase: ").encode())]

            with AgeReader(args.infile, identities=identities) as agereader:
                while chunk := agereader.read(DATA_CHUNK_SIZE):
                    try:
                        writeall(args.outfile, chunk)
                    except BrokenPipeError:
                        break


if __name__ == "__main__":
    main()
