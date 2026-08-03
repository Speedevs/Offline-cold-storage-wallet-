# SeedForge `.vlk` Vault Format (v1)

There is no universally-agreed `.vlk` standard, so this document specifies the
one SeedForge writes so that the format is auditable and re-implementable — not
a black box. A `.vlk` file is a password-encrypted container holding one BIP-39
mnemonic and a little non-secret metadata. Without the password it reveals
nothing except the KDF parameters.

## Cryptography

| Stage | Algorithm | Notes |
|---|---|---|
| Key derivation | **Argon2id** | memory-hard; resists GPU/ASIC cracking |
| Encryption | **XChaCha20-Poly1305** | AEAD, 256-bit key, 192-bit random nonce |
| Integrity | Poly1305 tag over ciphertext **and** header (as AAD) | tamper-evident |

Default Argon2id cost: `time=3`, `memory=131072 KiB (128 MiB)`, `lanes=4`,
32-byte output. The parameters are stored in the header so files remain readable
if defaults change later; because the header is authenticated, they cannot be
downgraded by an attacker without breaking decryption.

## Byte layout

All multi-byte integers are big-endian. The file is `header || ciphertext`.

```
Offset  Size  Field
0       4     magic = ASCII "VLK1"
4       1     version = 0x01
5       1     kdf id  = 0x01 (Argon2id)
6       4     argon2 time (passes)
10      4     argon2 memory, in KiB
14      1     argon2 lanes (parallelism)
15      1     salt length = 16
16      16    salt (random)
32      1     nonce length = 24
33      24    nonce (random, XChaCha20-Poly1305)
57      ..    ciphertext = AEAD.Seal(plaintext) incl. trailing 16-byte tag
```

Bytes `0..56` (the whole header, magic through nonce) are passed to the AEAD as
**Additional Authenticated Data**. They are not encrypted, but they are
authenticated: any edit invalidates the tag.

## Plaintext

The encrypted plaintext is UTF-8 JSON:

```json
{
  "type": "seedforge-vault",
  "mnemonic": "word1 word2 ... wordN",
  "words": 24,
  "note": "optional non-secret label",
  "created": "2026-08-03T00:00:00Z"
}
```

The optional BIP-39 passphrase (25th word) is **never** stored — only the
mnemonic. A vault therefore reconstructs the same wallet only when combined with
whatever passphrase you use separately.

## Decryption procedure

1. Read and validate the header; recover `salt`, `nonce`, and Argon2 parameters.
2. `key = Argon2id(password, salt, time, memory, lanes, 32)`.
3. `plaintext = XChaCha20Poly1305(key).Open(nonce, ciphertext, aad=header)`.
   If the tag fails, the password is wrong **or** the file is corrupt — the two
   are deliberately indistinguishable (no password oracle).
4. Parse the JSON; confirm `type == "seedforge-vault"`.

## Operational guidance

- A `.vlk` is safe to store in cloud storage, on a USB stick, or emailed to
  yourself — its security rests entirely on the password's strength, so use a
  long, high-entropy passphrase.
- It is **not** a substitute for an offline written backup of the words
  themselves; treat it as a convenience/redundancy layer, and keep at least one
  copy of the phrase on paper or metal.
- For splitting a backup across people/locations with no single point of
  compromise, use the Shamir `split`/`combine` commands instead of (or in
  addition to) a vault.
