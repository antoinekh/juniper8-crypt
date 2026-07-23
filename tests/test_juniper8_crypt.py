"""pytest suite for juniper8_crypt."""

import pytest

from juniper8_crypt import MAGIC, __version__, check, decrypt, encrypt, main


# Master password and $8$ values captured from a real JUNOS 23.2 device.
MASTER = "a3f8d9e112c04b7af1c3e8b92d057a4e"

KNOWN_VECTORS = [
    (
        "$8$aes256-gcm$hmac-sha2-256$100$p8XEvHtxRNE$d/hqRmh5etkBzo7WSdtvjg$"
        "7w1eMTYXkz4RdzMF9CAkJQ$qVLunbFwBWwyxln2Vg",
        "LabBgpSecret1",
    ),
    (
        "$8$aes256-gcm$hmac-sha2-256$100$32kBriS21/k$0O08cy0znzu4nrcHxbhMmA$"
        "PP0OeY9ANX2UDT1FTDVpiQ$gTrzX/ZppBbu42TpRtw",
        "LabIsisSecret1",
    ),
]

ROUNDTRIP_PLAINTEXTS = [
    "a",
    "hello",
    "L@bS3cr3t!",
    "LabBgpSecret1",
    "0" * 20,
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
    "!@#$%^&*()_+-=[]{}|;':\",./<>?",
    "café",
    "",
]


@pytest.mark.parametrize("ciphertext,expected", KNOWN_VECTORS)
def test_decrypt_known_vectors(ciphertext: str, expected: str) -> None:
    assert decrypt(ciphertext, MASTER) == expected


@pytest.mark.parametrize("plaintext", ROUNDTRIP_PLAINTEXTS)
def test_roundtrip(plaintext: str) -> None:
    assert decrypt(encrypt(plaintext, MASTER), MASTER) == plaintext


def test_encrypt_starts_with_magic() -> None:
    assert encrypt("hello", MASTER).startswith(MAGIC)


def test_encrypt_is_nondeterministic() -> None:
    results = {encrypt("test", MASTER) for _ in range(20)}
    assert len(results) > 1


def test_decrypt_wrong_master_fails() -> None:
    ciphertext = KNOWN_VECTORS[0][0]
    with pytest.raises(ValueError, match="[Aa]uthentication failed"):
        decrypt(ciphertext, "wrong-master-password")


def test_decrypt_missing_magic() -> None:
    with pytest.raises(ValueError, match=r"\$8\$"):
        decrypt("plaintext", MASTER)


def test_decrypt_malformed_fields() -> None:
    with pytest.raises(ValueError, match="Malformed"):
        decrypt("$8$aes256-gcm$hmac-sha2-256$100$short", MASTER)


def test_decrypt_unsupported_crypt_algo() -> None:
    with pytest.raises(ValueError, match="crypt-algo"):
        decrypt("$8$aes128-gcm$hmac-sha2-256$100$a$b$c$d", MASTER)


def test_decrypt_invalid_iterations() -> None:
    with pytest.raises(ValueError, match="iteration"):
        decrypt("$8$aes256-gcm$hmac-sha2-256$xx$a$b$c$d", MASTER)


@pytest.mark.parametrize("digits", ["²", "١٠٠"])
def test_decrypt_rejects_non_ascii_iterations(digits: str) -> None:
    # str.isdigit() is True for non-ASCII digits. Superscripts ("²") make int()
    # fail with a generic parsing error, while Arabic-Indic digits ("١٠٠") parse
    # cleanly and slip past validation entirely. Both must be rejected here.
    ciphertext = KNOWN_VECTORS[0][0].replace("$100$", f"${digits}$", 1)
    with pytest.raises(ValueError, match="Invalid iteration count"):
        decrypt(ciphertext, MASTER)


def test_decrypt_iterations_out_of_range() -> None:
    # A hostile value must not force an arbitrarily expensive PBKDF2 derivation.
    with pytest.raises(ValueError, match="out of range"):
        decrypt("$8$aes256-gcm$hmac-sha2-256$99999999$a$b$c$d", MASTER)


def test_decrypt_invalid_base64() -> None:
    with pytest.raises(ValueError, match="[Bb]ase64"):
        decrypt("$8$aes256-gcm$hmac-sha2-256$100$!!!!$b$c$d", MASTER)


def test_check_against_plaintext() -> None:
    _, _, match = check(encrypt("s3cr3t", MASTER), "s3cr3t", MASTER)
    assert match


def test_check_against_ciphertext_same_plaintext() -> None:
    a = encrypt("s3cr3t", MASTER)
    b = encrypt("s3cr3t", MASTER)
    assert a != b
    _, _, match = check(a, b, MASTER)
    assert match


def test_check_against_ciphertext_different_plaintext() -> None:
    _, _, match = check(encrypt("foo", MASTER), encrypt("bar", MASTER), MASTER)
    assert not match


def test_cli_decrypt(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--master", MASTER, "--decrypt", KNOWN_VECTORS[0][0]])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "LabBgpSecret1"


def test_cli_check_match_exits_zero() -> None:
    rc = main(["--master", MASTER, "--check", KNOWN_VECTORS[0][0], "LabBgpSecret1"])
    assert rc == 0


def test_cli_check_mismatch_exits_one() -> None:
    rc = main(["--master", MASTER, "--check", KNOWN_VECTORS[0][0], "nope"])
    assert rc == 1


def test_cli_invalid_input_exits_two(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--master", MASTER, "--decrypt", "plaintext"])
    assert rc == 2
    assert "error" in capsys.readouterr().err


def test_cli_encrypt_roundtrips(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--master", MASTER, "--encrypt", "hello"])
    assert rc == 0
    assert decrypt(capsys.readouterr().out.strip(), MASTER) == "hello"


def test_cli_master_from_env(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("JUNOS_MASTER_PASSWORD", MASTER)
    rc = main(["--decrypt", KNOWN_VECTORS[0][0]])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "LabBgpSecret1"


def test_cli_master_arg_overrides_env(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("JUNOS_MASTER_PASSWORD", "wrong-master")
    rc = main(["--master", MASTER, "--decrypt", KNOWN_VECTORS[0][0]])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "LabBgpSecret1"


def test_cli_master_from_prompt(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("JUNOS_MASTER_PASSWORD", raising=False)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": MASTER)
    rc = main(["--decrypt", KNOWN_VECTORS[0][0]])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "LabBgpSecret1"


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out
