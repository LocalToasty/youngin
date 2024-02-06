# pyage: a library for transparent encryption and decryption

This package is an implementation of the [age encryption format][age].  It
supports the linear writing as well as seekable reading of age-encrypted files.

[age]: https://age-encryption.org/v1

## Asymmetric reading and writing

 1. **Generate a keypair**

    ```
    $ pyage keygen -o keyfile
    Public key: age1f2jle9xffuv0wgck3c5yj7rf6mc9knfzhrmy7w4a55fx6eavr3qs55z8jd
    ```
    The public key may be freely shared.  It will later be used to encrypt the data.
    
    If decryption will take place in an interactive environment, you may even want to encrypt your private key:
    ```
    $ pyage keygen | pyage encrypt -o keyfile.age
    Public key: age1f2jle9xffuv0wgck3c5yj7rf6mc9knfzhrmy7w4a55fx6eavr3qs55z8jd
    Enter passphrase: [INPUT HIDDEN]
    Confirm passphrase: [INPUT HIDDEN]
    ```

 2. **Write to an encrypted file in your code**

    `AgeWriter` can be used in many contexts a normal file would be used.
    ```python
    import pandas as pd
    from pyage import AgeWriter, X25519Recipient

    d = {'col1': [1, 2], 'col2': [3, 4]}
    df = pd.DataFrame(data=d)

    with AgeWriter(
        "data.csv.age", recipients=[
            X25519Recipient.from_public_key("age1f2jle9xffuv0wgck3c5yj7rf6mc9knfzhrmy7w4a55fx6eavr3qs55z8jd"),
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
    from pyage import AgeReader

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
    from pyage import AgeReader, X25519Identity, ScryptPassphrase
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

```
$ pyage encrypt \
    -r age1f2jle9xffuv0wgck3c5yj7rf6mc9knfzhrmy7w4a55fx6eavr3qs55z8jd \
    -o encrypted.txt.age \
    file.txt
```

### Decryption

```
$ pyage decrypt -i keyfile -o decrypted.txt encrypted.txt.age
```