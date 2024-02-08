#!/usr/bin/env python3
"""CLI interface for youngin.

This interface can be used to generate keys, encrypt and decrypt files.
"""
import io
import os
import sys
from argparse import ArgumentParser, FileType
from collections.abc import Iterable
from datetime import datetime
from functools import partial
from getpass import getpass
from pathlib import Path
from typing import BinaryIO, TextIO

from . import (
    AgeReader,
    AgeWriter,
    Identity,
    Recipient,
    ScryptPassphrase,
    X25519Identity,
    X25519Recipient,
)
from .age import DATA_CHUNK_SIZE, writeall


def main() -> None:
    """Entrypoint for the CLI."""
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
        type=Path,
        default=[],
        metavar="IDENTITYFILE",
        dest="identity_file_paths",
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
            if args.output == "-":
                keygen_(sys.stdout)
            else:
                with open(
                    args.output,
                    "w",
                    encoding="ascii",
                    opener=partial(os.open, mode=0o600),
                ) as outfile:
                    keygen_(outfile)

        case "encrypt":
            encrypt_(
                recipients=args.recipients, infile=args.infile, outfile=args.outfile
            )

        case "decrypt":
            decrypt_(args.identity_file_paths, infile=args.infile, outfile=args.outfile)


def keygen_(outfile: TextIO) -> None:
    """Generate a key"""
    identity = X25519Identity.generate()
    recipient = identity.recipient()

    outfile.write(f"# created: {datetime.now().astimezone().isoformat()}\n")
    outfile.write(f"# public key: {recipient}\n")
    outfile.write(f"{identity}\n")

    if not outfile.isatty():
        sys.stderr.write(f"Public key: {recipient}\n")


def encrypt_(
    recipients: Iterable[Recipient], infile: BinaryIO, outfile: BinaryIO
) -> None:
    """Encrypt a file"""
    if not recipients:
        # Ask for passphrase
        passphrase = getpass("Enter passphrase: ")
        if passphrase != getpass("Confirm passphrase: "):
            raise RuntimeError("passphrases didn't match")
        recipients = [ScryptPassphrase(passphrase=passphrase.encode())]

    with AgeWriter(outfile, recipients=recipients) as agewriter:
        while chunk := infile.read(DATA_CHUNK_SIZE):
            agewriter.write(chunk)


def decrypt_(identity_file_paths: Iterable[Path], infile: io.IOBase, outfile: BinaryIO) -> None:
    """Decrypt a file"""
    identities: list[Identity] = []
    # Gather identities, either from one of the key files or as a provided if
    # none is provided
    if identity_file_paths:
        for identity_file_path in identity_file_paths:
            with open(identity_file_path, "rb") as identity_file:
                magic = identity_file.peek(len(b"age-encryption.org/v1\n"))
                if magic.startswith(b"age-encryption.org/v1\n"):
                    passphrase = getpass(f"Enter passphrase for {identity_file_path}: ")
                    identities += X25519Identity.from_keyfile(
                        identity_file,
                        identities=[ScryptPassphrase(passphrase.encode())],
                    )
                else:
                    identities += X25519Identity.from_keyfile(identity_file)
    else:
        identities = [ScryptPassphrase(getpass("Enter passphrase: ").encode())]

    with AgeReader(infile, identities=identities) as agereader:
        while chunk := agereader.read(DATA_CHUNK_SIZE):
            try:
                writeall(outfile, chunk)
            except BrokenPipeError:
                break


if __name__ == "__main__":
    main()
