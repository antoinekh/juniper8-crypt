"""
Encrypt and decrypt Juniper $8$ (type 8) passwords.

Unlike the reversible, keyless $9$ substitution cipher, the $8$ format is
genuine authenticated encryption keyed by the device master password
(``set system master-password``). The same master password is required to
both encrypt and decrypt: without it, $8$ secrets cannot be recovered.

Juniper documents the format, but the documentation is incomplete: it omits
that only the first 12 bytes of the 16-byte iv field are used as the GCM
nonce, so a by-the-book implementation fails authentication. That missing
detail was reverse-engineered and verified against a real JUNOS 23.2 device
(tag authentication passes):

    $8$<crypt-algo>$<hash-algo>$<iterations>$<salt>$<iv>$<tag>$<ciphertext>

* encoding : standard base64 (RFC 4648), no padding, for every binary field.
* key      : PBKDF2-HMAC-SHA256(master_password, salt, iterations) -> 32 bytes.
* cipher   : AES-256-GCM, no additional authenticated data (AAD).
* nonce    : the iv field decodes to 16 bytes, but only the first 12 are used
             as the GCM nonce; the trailing 4 bytes are unused padding.

Public API:
    decrypt(ciphertext: str, master_password: str) -> str
    encrypt(plaintext: str, master_password: str) -> str
    check(ciphertext: str, other: str, master_password: str) -> tuple[str, str, bool]
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import os
import sys
from importlib.metadata import version

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__version__ = version("juniper8-crypt")

__all__ = ["decrypt", "encrypt", "check", "__version__"]

MAGIC = "$8$"

# Environment variable the CLI reads the master password from when --master
# is not given on the command line.
ENV_MASTER = "JUNOS_MASTER_PASSWORD"

# Fixed algorithm parameters JUNOS currently emits for type 8.
CRYPT_ALGO = "aes256-gcm"
HASH_ALGO = "hmac-sha2-256"
DEFAULT_ITERATIONS = 100
# Bounds JUNOS accepts for the type 8 iteration count. Enforced on decrypt so a
# hostile $8$ value cannot force an arbitrarily expensive PBKDF2 derivation.
MIN_ITERATIONS = 10
MAX_ITERATIONS = 10000
SALT_LEN = 8  # bytes
IV_LEN = 16  # bytes stored in the string
NONCE_LEN = 12  # bytes of the IV actually used as the GCM nonce
KEY_LEN = 32  # bytes, AES-256
TAG_LEN = 16  # bytes, GCM authentication tag


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except binascii.Error as e:
        raise ValueError(f"Invalid base64 in $8$ value: {text!r}") from e


def _derive_key(master_password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(), length=KEY_LEN, salt=salt, iterations=iterations
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt(plaintext: str, master_password: str) -> str:
    """Encrypt plaintext into a Juniper $8$ value under master_password.

    Output is non-deterministic: a fresh random salt and IV are generated on
    every call, so the same plaintext produces a different $8$ string each
    time. All of them decrypt back to the same plaintext with the same master
    password.
    """
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = _derive_key(master_password, salt, DEFAULT_ITERATIONS)

    # JUNOS uses only the first 12 IV bytes as the GCM nonce. AESGCM appends
    # the authentication tag to the ciphertext.
    sealed = AESGCM(key).encrypt(iv[:NONCE_LEN], plaintext.encode("utf-8"), None)
    ciphertext, tag = sealed[:-TAG_LEN], sealed[-TAG_LEN:]

    return MAGIC + "$".join(
        [
            CRYPT_ALGO,
            HASH_ALGO,
            str(DEFAULT_ITERATIONS),
            _b64encode(salt),
            _b64encode(iv),
            _b64encode(tag),
            _b64encode(ciphertext),
        ]
    )


def decrypt(ciphertext: str, master_password: str) -> str:
    """Decrypt a Juniper $8$ value with master_password.

    Raises ValueError on a malformed $8$ string or on authentication failure
    (wrong master password, or a value not produced by this scheme).
    """
    if not ciphertext.startswith(MAGIC):
        raise ValueError(f"Not a Juniper $8$ string: must start with {MAGIC}")

    # Leading '$' yields an empty first element; '8' is the type tag.
    parts = ciphertext.split("$")
    if len(parts) != 9:
        raise ValueError("Malformed $8$ value: expected 7 fields after the prefix")
    _, _type, crypt_algo, hash_algo, iters, salt_b, iv_b, tag_b, ct_b = parts

    if crypt_algo != CRYPT_ALGO:
        raise ValueError(f"Unsupported crypt-algo {crypt_algo!r}: only {CRYPT_ALGO}")
    if hash_algo != HASH_ALGO:
        raise ValueError(f"Unsupported hash-algo {hash_algo!r}: only {HASH_ALGO}")
    if not iters.isdigit():
        raise ValueError(f"Invalid iteration count: {iters!r}")
    if not MIN_ITERATIONS <= int(iters) <= MAX_ITERATIONS:
        raise ValueError(
            f"Iteration count {iters} out of range "
            f"({MIN_ITERATIONS}-{MAX_ITERATIONS})"
        )

    salt, iv, tag, ct = (
        _b64decode(salt_b),
        _b64decode(iv_b),
        _b64decode(tag_b),
        _b64decode(ct_b),
    )
    key = _derive_key(master_password, salt, int(iters))
    try:
        plaintext = AESGCM(key).decrypt(iv[:NONCE_LEN], ct + tag, None)
    except InvalidTag as e:
        raise ValueError(
            "Authentication failed: wrong master password, or the value was "
            "not produced by this scheme"
        ) from e
    return plaintext.decode("utf-8")


def check(
    ciphertext: str, other: str, master_password: str
) -> tuple[str, str, bool]:
    """Decrypt `ciphertext` and compare to `other`.

    `other` may be a plaintext, or another $8$ value (auto-detected by the
    $8$ prefix and decrypted with the same master password). Returns
    (plain_a, plain_b, match).
    """
    plain_a = decrypt(ciphertext, master_password)
    plain_b = (
        decrypt(other, master_password) if other.startswith(MAGIC) else other
    )
    return plain_a, plain_b, plain_a == plain_b


def _resolve_master(arg: str | None) -> str:
    """Resolve the master password from --master, the environment, or a prompt.

    Precedence: the explicit CLI value, then the ENV_MASTER environment
    variable, then an interactive no-echo prompt. The CLI value is convenient
    but leaks into shell history and the process list, so the environment
    variable or the prompt are preferred for anything sensitive.
    """
    if arg is not None:
        return arg
    env = os.environ.get(ENV_MASTER)
    if env is not None:
        return env
    return getpass.getpass("Master password: ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="juniper8-crypt",
        description="Encrypt, decrypt, or compare Juniper $8$ (type 8) passwords.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-m",
        "--master",
        metavar="MASTER",
        help=(
            "Master password (set system master-password) used to derive the "
            f"key. If omitted, it is read from the {ENV_MASTER} environment "
            "variable, or prompted for without echo."
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--decrypt", metavar="CIPHERTEXT", help="Decrypt a $8$ value")
    group.add_argument("--encrypt", metavar="PLAINTEXT", help="Encrypt a plaintext value")
    group.add_argument(
        "--check",
        nargs=2,
        metavar=("CIPHERTEXT", "VALUE"),
        help="Decrypt and compare. VALUE is a plaintext or another $8$ value. Exit 0 on match, 1 on mismatch.",
    )
    args = parser.parse_args(argv)
    master = _resolve_master(args.master)

    try:
        if args.decrypt is not None:
            print(decrypt(args.decrypt, master))
        elif args.encrypt is not None:
            print(encrypt(args.encrypt, master))
        elif args.check is not None:
            plain_a, plain_b, match = check(*args.check, master)
            print(f"Value 1   : {plain_a!r}")
            print(f"Value 2   : {plain_b!r}")
            print(f"Match     : {'YES' if match else 'NO'}")
            return 0 if match else 1
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
