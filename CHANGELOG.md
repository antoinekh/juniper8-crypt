# Changelog

## v0.2.0 - 2026-07-23

### Deprecated

- This package is superseded by [network-secret](https://github.com/antoinekh/network-secret), which unifies `juniper8-crypt`, `juniper9-crypt`, and the Nokia SR OS custom-hash cipher. The repository is now read-only; the README carries the migration notice.

### Fixed

- `decrypt()` now rejects iteration counts written with non-ASCII digits. `str.isdigit()` accepts them, so superscripts such as `²` escaped with a generic `int()` parsing error, and Arabic-Indic digits such as `١٠٠` parsed cleanly and bypassed the field validation altogether.

### Changed

- CI: dropped the redundant `uv python install` step; `uv run --python` installs the interpreter on demand.

### Docs

- README: link the browser-based encoder/decoder at [network-secret-website.pages.dev](https://network-secret-website.pages.dev/).
- Correct the "undocumented" framing: Juniper does document the `$8$` format, but the docs omit that the 16-byte IV is truncated to its first 12 bytes for the GCM nonce; that missing detail is what was reverse-engineered. Updated the README and the module docstring.

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
