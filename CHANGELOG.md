# Changelog

## Unreleased

### Docs

- README: link the browser-based encoder/decoder at [network-secret-decoder.pages.dev](https://network-secret-decoder.pages.dev/).

## v0.1.0 - 2026-06-16

- Initial release: `decrypt()`, `encrypt()`, `check()` Python API and the
  `juniper8-crypt` CLI for Juniper `$8$` (type 8) passwords.
- Algorithm reverse-engineered and verified against a real JUNOS 23.2 device:
  standard-base64 fields, PBKDF2-HMAC-SHA256 key derivation, AES-256-GCM with
  the GCM nonce taken from the first 12 bytes of the 16-byte IV field.
- CLI: master password from `--master`, the `JUNOS_MASTER_PASSWORD` environment
  variable, or an interactive no-echo prompt (in that order of precedence).
- Hardened decrypt: enforces the documented PBKDF2 iteration range (10-10000)
  and rejects malformed base64 fields strictly.
</content>
</invoke>
