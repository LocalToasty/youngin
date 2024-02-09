# youngin: a library for transparent encryption and decryption

This package is an implementation of the [age encryption format][age].  It
supports the linear writing as well as seekable reading of age-encrypted files.

[age]: https://age-encryption.org/v1


## Asymmetric encryption

In most cases, asymmetric encryption should be be the preferred way to use
youngin.

 1. **Generate a keypair**

    ```
    $ youngin keygen -o keyfile
    Public key: age1f2jle9xffuv0wgck3c5yj7rf6mc9knfzhrmy7w4a55fx6eavr3qs55z8jd
    ```
    The public key may be freely shared.  It will later be used to encrypt the data.
    
    If decryption will take place in an interactive environment, you may even
    want to encrypt your private key:
    ```
    $ youngin keygen | youngin encrypt -o keyfile.age
    Public key: age1f2jle9xffuv0wgck3c5yj7rf6mc9knfzhrmy7w4a55fx6eavr3qs55z8jd
    Enter passphrase: [INPUT HIDDEN]
    Confirm passphrase: [INPUT HIDDEN]
    ```

 2. **Write to an encrypted file in your code**

    `AgeWriter` can be used in many contexts a normal file would be used.
    ```python
    import pandas as pd
    from youngin import AgeWriter, X25519Recipient

    d = {'col1': [1, 2], 'col2': [3, 4]}
    df = pd.DataFrame(data=d)

    with AgeWriter(
        "data.csv.age", recipients=[
            X25519Recipient.from_public_key("age1f2jle9xffuv0wgck3c5yj7rf6mc9knfzhrmy7w4a55fx6eavr3qs55z8jd"),
            X25519Recipient.from_public_key("age1w75vnxy3zuyu3dx0tamxx7qlf4aux2vfn0xn7atwpug3cdsr0p4qey3fhg"),
        ]
    ) as agefile:
        df.to_csv(agefile)
    ```

    Other common libraries which can be used this way are `pillow`
    (`im.save(agefile, format="png")`) and python's `zipfile` (`with
    ZipFile(agefile, "wb") as zip: ...`).

 2. **Open an encrypted file in your code**

    Similarly, `AgeReader` object can be used to read from encrypted files:
    ```python
    import pandas as pd
    from youngin import AgeReader

    with AgeReader(
        "data.csv.age",
        identites=X25519Identity.from_key_file("keyfile"),
    ) as agefile:
        df = pd.read_csv(agefile)
    ```

    In case you protected your keyfile with a passphrase, you can interactively
    query for it like this:
    ```python
    import pandas as pd
    from youngin import AgeReader, X25519Identity, ScryptPassphrase
    from getpass import getpass

    passphrase = getpass().encode()
    identites=X25519Identity.from_key_file(
        "keyfile.age",
        identities=[ScryptPassphrase(passphrase)])

    with AgeReader("data.csv.age", identities=identities) as agefile:
        df = pd.read_csv(agefile)
    ```

## Using the CLI

Alternatively, this package also includes a CLI to encrypt and decrypt files.

### Encryption

You can asymetrically encrypt files by supplying one or multiple recipients
using the `-r` flag:
```
$ youngin encrypt \
    -r age1f2jle9xffuv0wgck3c5yj7rf6mc9knfzhrmy7w4a55fx6eavr3qs55z8jd \
    -r age1w75vnxy3zuyu3dx0tamxx7qlf4aux2vfn0xn7atwpug3cdsr0p4qey3fhg \
    -o encrypted.txt.age \
    file.txt
```
If you don't specify any recipients, you will instead be prompted for a password
which will be used to symmetrically encrypt the file.

### Decryption

To decrypt an asymmetrically encrypted file, you have to supply your private key
file using the `-i` flag:
```
$ youngin decrypt -i keyfile -o decrypted.txt encrypted.txt.age
```

## TODOs

  - Recipient files in the CLI interface
  - Support for SSH ed25519 keys
  - Simultaneous read-write support