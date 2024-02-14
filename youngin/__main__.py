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
from .reader import DATA_CHUNK_SIZE
from .writer import writeall


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
        default=[],
        action="append",
    )
    encrypt_parser.add_argument(
        "--recipients-file",
        "-R",
        metavar="PATH",
        dest="recipients",
        type=lambda p: list(X25519Recipient.from_recipient_file(p)),
        default=[],
        action="append",
    )
    encrypt_parser.add_argument(
        "--passphrase",
        "-p",
        dest="read_passphrase",
        action="store_true",
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
                recipients=args.recipients,
                read_passphrase=args.read_passphrase,
                infile=args.infile,
                outfile=args.outfile,
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
    recipients: Iterable[Recipient | Iterable[Recipient]],
    read_passphrase: bool,
    infile: BinaryIO,
    outfile: io.BufferedIOBase,
) -> None:
    """Encrypt a file"""
    flattened_recipients: list[Recipient] = []
    for recipient in recipients:
        if isinstance(recipient, Recipient):
            flattened_recipients.append(recipient)
        else:
            flattened_recipients += recipient

    if read_passphrase:
        if flattened_recipients:
            raise RuntimeError(
                "passphrase cannot be set in conjunction with recipients"
            )
        # Ask for passphrase
        passphrase = getpass("Enter passphrase: ")
        if passphrase != getpass("Confirm passphrase: "):
            raise RuntimeError("passphrases didn't match")
        flattened_recipients = [ScryptPassphrase(passphrase=passphrase.encode())]

    if not flattened_recipients:
        raise RuntimeError("either a recipient or a passphrase has to be specified")

    with AgeWriter(outfile, recipients=flattened_recipients) as agewriter:
        while chunk := infile.read(DATA_CHUNK_SIZE):
            agewriter.write(chunk)


def decrypt_(
    identity_file_paths: Iterable[Path], infile: io.IOBase, outfile: io.BufferedIOBase
) -> None:
    """Decrypt a file"""
    identities: list[Identity] = []
    # Gather identities, either from one of the key files or as a provided if
    # none is provided
    if identity_file_paths:
        for identity_file_path in identity_file_paths:
            with open(identity_file_path, "rb") as identity_file:
                identities += X25519Identity.from_keyfile(
                    identity_file,
                    identities="interactive",
                )
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
