# juniper8-crypt

[![tests](https://github.com/antoinekh/juniper8-crypt/actions/workflows/test.yml/badge.svg)](https://github.com/antoinekh/juniper8-crypt/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/juniper8-crypt)](https://pypi.org/project/juniper8-crypt/)
[![Python versions](https://img.shields.io/pypi/pyversions/juniper8-crypt)](https://pypi.org/project/juniper8-crypt/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Encrypt and decrypt Juniper `$8$` (type 8) passwords, from the command line or Python.

The `$8$` format is **genuine authenticated encryption**, keyed by the device master password (`set system master-password`). Unlike the reversible, keyless `$9$` substitution cipher, a `$8$` secret cannot be recovered without that master password: the same master password is required to both encrypt and decrypt.

> **Prefer a browser?** Encode and decode `$8$` (and `$9$`, and Nokia SR OS custom-hash) at **[network-secret-decoder.pages.dev](https://network-secret-decoder.pages.dev/)**. It runs the same algorithm fully client-side - nothing you type is ever sent to a server.

> Juniper [documents the `$8$` format](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/master-password-configuration-encryption.html) (AES256-GCM, PBKDF2, the field layout, the ASCII64/base64 encoding), but the documentation is incomplete in the one way that matters: it never states that the 16-byte `iv` field is truncated to its first 12 bytes for the GCM nonce. Implement it by the book and the authentication tag never verifies, which is why no public decoder existed. That missing detail was reverse-engineered and verified against a real JUNOS 23.2 device (the GCM authentication tag verifies). See [Algorithm](#algorithm) for the full details.

## Run without installing

If you have [uv](https://github.com/astral-sh/uv) installed, `uvx` runs the CLI without installing anything:

```bash
uvx juniper8-crypt --master 'MySecretMasterPw' --decrypt '$8$aes256-gcm$hmac-sha2-256$100$p8XEvHtxRNE$d/hqRmh5etkBzo7WSdtvjg$7w1eMTYXkz4RdzMF9CAkJQ$qVLunbFwBWwyxln2Vg'
```


## Install

```bash
pip install juniper8-crypt
```

Or with `uv`:

```bash
uv add juniper8-crypt
```

## Command-line usage

Every operation needs the master password. You can supply it three ways, in order of precedence:

1. `--master`/`-m` on the command line,
2. the `JUNOS_MASTER_PASSWORD` environment variable,
3. an interactive no-echo prompt (used when neither of the above is set).

```bash
# Decrypt a $8$ value (master on the command line)
juniper8-crypt --master 'MyMaster' --decrypt '$8$aes256-gcm$hmac-sha2-256$100$...'

# Encrypt a plaintext
juniper8-crypt --master 'MyMaster' --encrypt 'LabBgpSecret1'

# Check a $8$ value against a plaintext or another $8$ value
juniper8-crypt --master 'MyMaster' --check '$8$...' 'LabBgpSecret1'
juniper8-crypt --master 'MyMaster' --check '$8$...' '$8$...'

# Master from the environment (keeps it out of shell history / the process list)
export JUNOS_MASTER_PASSWORD='MyMaster'
juniper8-crypt --decrypt '$8$aes256-gcm$hmac-sha2-256$100$...'

# Master from an interactive prompt (nothing on the command line or in the env)
juniper8-crypt --decrypt '$8$aes256-gcm$hmac-sha2-256$100$...'
# Master password: ‹typed without echo›
```

> Passing `--master` on the command line is convenient but leaks the secret into your shell history and the process list (`ps`). Prefer `JUNOS_MASTER_PASSWORD` or the prompt for anything sensitive.
>
> Always quote `$8$` strings with single quotes - the shell expands `$8` as a positional parameter otherwise.

### Exit codes

| Code | Meaning                                             |
|------|-----------------------------------------------------|
| 0    | Success (or `--check` matched)                      |
| 1    | `--check` mismatched                                |
| 2    | Invalid input (malformed value, wrong master, etc.) |

### Example output

```console
$ juniper8-crypt --master 'a3f8d9e112c04b7af1c3e8b92d057a4e' \
    --decrypt '$8$aes256-gcm$hmac-sha2-256$100$p8XEvHtxRNE$d/hqRmh5etkBzo7WSdtvjg$7w1eMTYXkz4RdzMF9CAkJQ$qVLunbFwBWwyxln2Vg'
LabBgpSecret1

$ juniper8-crypt --master 'a3f8d9e112c04b7af1c3e8b92d057a4e' --encrypt 'LabBgpSecret1'
$8$aes256-gcm$hmac-sha2-256$100$wh8cAoBCbnY$hON9pWdcoFECAJYdqwr3+A$IyYbHprOWFigR4titT+CxA$NWh8D/XOgwafCuK6TQ

$ juniper8-crypt --master 'a3f8d9e112c04b7af1c3e8b92d057a4e' \
    --check '$8$aes256-gcm$hmac-sha2-256$100$p8XEvHtxRNE$d/hqRmh5etkBzo7WSdtvjg$7w1eMTYXkz4RdzMF9CAkJQ$qVLunbFwBWwyxln2Vg' 'LabBgpSecret1'
Value 1   : 'LabBgpSecret1'
Value 2   : 'LabBgpSecret1'
Match     : YES
```

`--encrypt` output varies on every run: a fresh random salt and IV are generated each time, so the same plaintext produces a different `$8$` string. They all decrypt back to the same plaintext with the same master password.

## Python API

```python
from juniper8_crypt import decrypt, encrypt, check

master = "a3f8d9e112c04b7af1c3e8b92d057a4e"

# Decrypt
plain = decrypt("$8$aes256-gcm$hmac-sha2-256$100$p8XEvHtxRNE$d/hqRmh5etkBzo7WSdtvjg$7w1eMTYXkz4RdzMF9CAkJQ$qVLunbFwBWwyxln2Vg", master)
# 'LabBgpSecret1'

# Encrypt (non-deterministic)
ciphertext = encrypt("LabBgpSecret1", master)
# '$8$aes256-gcm$hmac-sha2-256$100$...'  (a fresh value each call)

# Compare a $8$ value against a plaintext
plain_a, plain_b, match = check(ciphertext, "LabBgpSecret1", master)
assert match is True

# Compare two $8$ values
plain_a, plain_b, match = check(ciphertext, encrypt("LabBgpSecret1", master), master)
assert match is True
```

### Error handling

`decrypt()` raises `ValueError` for malformed inputs (missing `$8$` prefix, wrong field count, unsupported algorithm, invalid base64) and for authentication failure (wrong master password, or a value not produced by this scheme):

```python
from juniper8_crypt import decrypt

try:
    decrypt("$8$...", "wrong-master")
except ValueError as e:
    print(f"bad input: {e}")
```

## Tests

```bash
git clone https://github.com/antoinekh/juniper8-crypt
cd juniper8-crypt
uv run pytest -v
```

## Algorithm

![Juniper $8$ encryption overview](https://raw.githubusercontent.com/antoinekh/juniper8-crypt/master/docs/juniper8-algorithm.svg)

`$8$` is the JUNOS "type 8" format used for secrets the device must be able to recover in cleartext (BGP/IS-IS authentication keys, RADIUS secrets, etc.) once a master password is configured. It is real authenticated encryption: PBKDF2 stretches the master password into an AES key, and AES-256-GCM encrypts the secret and authenticates it with a tag.

### String layout

```text
$8$<crypt-algo>$<hash-algo>$<iterations>$<salt>$<iv>$<tag>$<ciphertext>
```

| Field        | Example         | Meaning                                               |
|--------------|-----------------|-------------------------------------------------------|
| `crypt-algo` | `aes256-gcm`    | Cipher. Only AES-256-GCM is currently emitted.        |
| `hash-algo`  | `hmac-sha2-256` | PBKDF2 PRF (HMAC-SHA-256).                            |
| `iterations` | `100`           | PBKDF2 iteration count (default 100, range 10-10000). |
| `salt`       | `p8XEvHtxRNE`   | 8 random bytes, the PBKDF2 salt.                      |
| `iv`         | `d/hqRmh5e...`  | 16 bytes; the GCM nonce is the **first 12**.          |
| `tag`        | `7w1eMTYX...`   | 16-byte GCM authentication tag.                       |
| `ciphertext` | `qVLunbFw...`   | The encrypted secret (same length as the plaintext).  |

Every binary field is **standard base64** (RFC 4648), with the `=` padding stripped.

### Building blocks

**1. Key derivation.** The master password (as UTF-8 bytes) is stretched with PBKDF2-HMAC-SHA256 over the `salt` for `iterations` rounds, producing a 32-byte AES-256 key:

```python
key = PBKDF2HMAC(SHA256(), length=32, salt=salt, iterations=iterations).derive(master.encode())
```

**2. Encryption.** AES-256-GCM encrypts the plaintext with **no additional authenticated data (AAD)**, producing the ciphertext and a 16-byte tag:

```python
nonce = iv[:12]                       # only the first 12 IV bytes are used
sealed = AESGCM(key).encrypt(nonce, plaintext, None)
ciphertext, tag = sealed[:-16], sealed[-16:]
```

**3. The IV gotcha.** This is the detail that defeats naive implementations. The `iv` field decodes to **16 bytes**, but JUNOS uses only the **first 12** as the GCM nonce (a standard 96-bit nonce); the trailing 4 bytes are random padding that is stored but never used. Feeding all 16 bytes to AES-GCM as the nonce produces a different counter stream and the tag never verifies.

### Decryption

1. Split the `$8$` string and base64-decode `salt`, `iv`, `tag`, `ciphertext`.
2. Re-derive the key with PBKDF2 from the master password and `salt`.
3. AES-256-GCM-decrypt `ciphertext` with nonce `iv[:12]`, verifying `tag`.
   A wrong master password (or any tampering) fails tag verification.

### Security note

`$8$` is real encryption, but its strength rests entirely on the master password. Treat the master password as a high-value secret; anyone holding it can decrypt every `$8$` value in a config.

## Credits

Juniper documents the `$8$` format, but the documentation is incomplete: it omits that the 16-byte `iv` field is truncated to its first 12 bytes for the GCM nonce (and the tag/salt lengths, the exact PRF, and the no-AAD detail). A by-the-book implementation therefore fails authentication, and as far as I could find there was no public decoder. The missing pieces were reverse-engineered with AI help: Claude ran the known-plaintext search, spotted that AES-GCM's ciphertext is independent of the tag and AAD (which made the search tractable), and identified the `iv[:12]` nonce quirk that defeats naive implementations.