# freshfix — recovering the stage-3 payload

Three scripts that take the public stage-3 Mach-O and produce its decrypted payload.
Everything here is static or emulated. **The sample is never executed.** Unicorn
interprets the instructions, every libSystem call is serviced in Python, and the emulator
has no filesystem, network or syscall access — so this is safe to run on a working
machine, unlike a VM detonation, which this sample would in any case notice.

Background and findings: [`stage4_payload.md`](../../campaigns/2026-08-04-cloudflare-clickfix/stage4_payload.md).

## Run it

```sh
cd tools/freshfix
uv sync

# 1. thin the universal binary
lipo -thin arm64 -output slice_arm64.bin /path/to/sample.bin

# 2. recover the 4-byte PBKDF2 password by emulating the loader's own arithmetic
uv run python emulate_key.py slice_arm64.bin

# 3. verify the HMAC routine, derive the key, decrypt the six AEAD chunks
uv run python decrypt_payload.py slice_arm64.bin -o payload_decrypted.bin

# 4. read the AppleScript literal table (UTF-16BE; strings(1) will not show it)
uv run python extract_scpt_strings.py payload_decrypted.bin --shell
```

Expected output for the reference sample:

```
loader   SHA256 29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40
password cb962534
dk       2778a0daaa066dd00b87a1338659b40d10f244df3d13cb08f0fd01dcd6f4bc89
payload  SHA256 95ab5a61a0970410ada36ba843e55e270f38cb8e2eebf79254434948e11c870f
```

All six Poly1305 tags must verify. If one fails, the key is wrong — the tags are the
correctness check, so there is no need to eyeball the plaintext to know whether it worked.

## Why emulation rather than brute force

The password is 32 bits, so exhaustive search with a Poly1305 oracle would also work, at
roughly 2³² × 98,222 × 2 SHA-256 operations. Emulation answers the same question in
seconds and, unlike brute force, also tells you *where* the value came from — which is how
the environmental-keying hypothesis was ruled out.

## If it does not reproduce on your sample

The scripts hardcode offsets from the reference build:

| Constant | Value | Meaning |
|---|---|---|
| `0x1000017e8` | — | `str w9, [sp, #0x9c]`, the only writer of the key slot |
| `0x10000322c` | — | `str w8, [sp, #0xfc]`, the derived password |
| `0x1000036d4` | — | HMAC-SHA256 |
| `SALT_OFF` | `0x80A0` | 32-byte PBKDF2 salt |
| `ITERATIONS` | `98222` | PBKDF2 iteration count |
| `LEN_TBL` | `0x5BF0` | six chunk lengths |
| `PTR_TBL` / `TAG_TBL` | `0x18FB0` / `0x18FE0` | ciphertext and tag pointers |

A different build will move these. The iteration count and the six-chunk structure come
from the packer and should hold; the addresses will not. `emulate_key.py` is the part
worth rerunning first — if the password comes out and decryption still fails, the offsets
are what drifted.

`decrypt_payload.py` accepts `--password` so you can feed a value recovered another way.

## Note on `osadecompile`

It will not help. The payload is exported run-only and `osadecompile` returns
`errOSASourceNotAvailable`. `extract_scpt_strings.py` exists because of that: the literal
table survives even when the source has been stripped.
