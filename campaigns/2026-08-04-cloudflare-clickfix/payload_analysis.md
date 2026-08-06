# Stage-2 and stage-3 analysis — campaign DANTE

**Campaign:** 2026-08-04 fake Cloudflare Turnstile, macOS
**Analysed:** 2026-08-06 · static only, nothing executed
**Assessed family:** AMOS (Atomic macOS Stealer) lineage — *assessed, not confirmed*
**Campaign marker:** `DANTE`

> Correction to the earlier writeup: it recorded the payload as unretrievable because
> the stage-1 gate burns its token on first contact. That held for the original token.
> A second visit yields a fresh one, and the chain was recovered end to end on
> 2026-08-06. The gate delays analysis; it does not prevent it.

---

## Chain

```
lure page                 clipboard write + Terminal instructions
  |
  v
stage 1  (zsh)            eval "$(printf '%s' <b64> | base64 -d)"
  |                       token gate -> "ok" exactly once
  v
stage 2  (zsh, gz+b64)    beacon: POST grove-89[.]com/api/metrics/run?event=pasted
  |                               headers: user: <id>, BuildID: <id>
  |                       fetch:  ferncurrent14[.]com/<b64ish>/DANTE/update -> /tmp/helper
  |                       xattr -c ; chmod +x ; run
  v
stage 3  (Mach-O)         self-decrypting loader -> in-memory infostealer
```

### Stage 1 — noise around one line

Roughly two thirds of the script is decoration: functions that only test `[ -d "$HOME" ]`,
loops that discard `$((RANDOM % 256))`, arrays never referenced, and a decoy base64 blob
(`etpuz87u`) that is defined and then ignored. The working part is one
`openssl base64 -d | gunzip` into a variable, followed by `eval`.

Worth noting for triage: AV coverage on this file was better than on the final Mach-O.
Detection was landing on the obfuscation shape, not on capability — which is exactly
backwards from a defender's point of view.

### Stage 2 — two requests, and the first one is the interesting one

Every string is built with `printf '\150\164\164\160...'` octal escapes, including the
names of the binaries invoked (`curl`, `xattr`, `chmod`). Simple to reverse, effective
against grep.

The first request is not part of the infection. It is a **conversion beacon**: a POST to
`grove-89[.]com/api/metrics/run?event=pasted`, fired the moment the victim pastes,
carrying two non-standard headers:

```
user:     Ag...
BuildID:  Ag...
```

This is affiliate telemetry — the operator is counting paste-through rate per build.

Two consequences for defenders. First, a hit on this beacon **precedes** the compromise:
between the beacon and the stage-3 fetch there is a window, small but real. Second, the
header *names* look more durable than the hosting, and are worth a network rule of their
own — see `detection/suricata/clickfix_dante_c2.rules`.

**Prior art, found late and worth stating plainly.** This pair is not our discovery. A
SigmaHQ emerging-threats rule published 2025-11-22 already matches on `user:` together
with `BuildID` in AMOS `curl` POSTs [12], built on a Trend Micro MDR analysis of an AMOS
campaign [13]. We found the headers independently and initially recorded them as the most
durable indicators in the chain; the first half of that is right, the novelty was not.

The upside outweighs the correction: an independent team observed the same two headers in
delivery they attribute to AMOS. That is the strongest single piece of corroboration for
the family assessment below, and it arrived from a direction we were not looking in — a
detection rule, not a threat report.

The second request retrieves the Mach-O to `/tmp/helper`, strips extended attributes with
`xattr -c`, sets the executable bit and runs it. The `xattr` step is load-bearing: without
it Gatekeeper would evaluate the binary on first launch.

---

## Stage 3 — the binary is a wrapper, not the stealer

| | |
|---|---|
| SHA256 (universal) | `29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40` |
| SHA256 (arm64) | `3873844f319ebbab08db2f27b6d7336a1d7d91ca65862d9470cd7300e4a3f207` |
| SHA256 (x86_64) | `3710bb59c25a1c7eaba2ab471876f223ed5d358fc08e979a2ff1ebeedf03e431` |
| MD5 (universal) | `ab477021780e553be4271cb34bb8394b` |
| Size | 297,968 bytes |
| Type | Universal Mach-O, x86_64 + arm64, PIE, C++ (`libc++`) |
| Signature | ad-hoc, identifier `setup-<40 hex>`, **no team ID** |

### The import table is the finding

Sixteen symbols. That is the whole external surface:

```
_getsectiondata, __dyld_get_image_header    locate own encrypted section
_mmap, _munmap                              anonymous memory
_mlock, _munlock                            keep plaintext out of swap
_dlsym                                      resolve every real API at runtime
_getenv                                     C2 configuration from environment
_pthread_main_np                            thread-context check
_memcpy, _bzero, _malloc, _free, _strstr    plumbing
___chkstk_darwin, dyld_stub_binder          runtime
```

No networking. No file I/O. No Security.framework. Not because the malware lacks those
capabilities, but because the loader does not need them — everything real is resolved
through `dlsym` after decryption.

The `mlock`/`munlock` pair deserves attention. The operator deliberately prevents the
decrypted payload from being written to swap. That is an anti-forensics measure aimed
squarely at post-incident memory and disk analysis, and it is uncommon enough in benign
software to carry weight in a detection rule.

`_getenv` matches the pattern reported elsewhere in this family, where C2 configuration
is handed to the payload through environment variables rather than embedded in the file.

### Where the stealer actually lives

`__DATA,__const` holds **69,632 bytes at entropy 7.9972** — indistinguishable from
random. The executable code in `__TEXT,__text` is 20,820 bytes. A ratio of 3.34 : 1
ciphertext to code: the program is a delivery vehicle for its own data section.

Strings are individually protected. The routine at `+0x36d4` is HMAC-based (ipad `0x36`,
opad `0x5c`, 64-byte block, 32-byte key), invoked per string with the plaintext length as
an argument. The disassembly shows the buffers being zero-filled immediately after use.
`strings` on the file returns two library paths and nothing else.

Recovering the payload would require emulating that decryption. Not attempted here; the
chain-level evidence was sufficient for triage, and the sample is public for anyone who
wants to go further.

---

## Attribution — and its limits

The chain matches published AMOS delivery in every observable respect: a `/curl/<hex>`
staging URL [1], several script stages with a base64-then-gunzip first stage and a Mach-O
dropped to `/tmp/helper` [2], `xattr -c` followed by `chmod +x`, and the
`<path>/<campaign>/update` URL shape that Jamf documented in April with a different
campaign token in the position ours fills with `DANTE` [3]. Unit 42 describes the modern
C++ "Odyssey" AMOS variant as a universal Intel/ARM64 binary written in C++ [4], which is
what this is.

Against that, three constraints:

- Microsoft states the same infrastructure cluster delivers **both** MacSync and AMOS [1].
  Chain shape does not separate them.
- Sophos independently reports MacSync variants adopting the identical social-engineering
  approach [5], and LevelBlue documents several competing groups sharing the ClickFix
  delivery method while deploying different families [7].
- SentinelOne notes that the Atomic family has splintered into rival offerings sold by
  competing vendors, and that researchers with far more samples than we have remain
  ambivalent about assigning individual samples [8].

The binary-level indicators — universal, C++, ad-hoc signed — are consistent with AMOS
but not exclusive to it.

**A fourth supporting point, added 2026-08-06:** the `user:` / `BuildID` header pair we
observed in stage 2 also appears in a SigmaHQ rule for Atomic macOS Stealer [12], derived
from a Trend Micro MDR investigation [13]. Two independent observations of the same
builder-emitted headers in AMOS-attributed delivery is a stronger link than anything the
chain shape alone provides.

It does not resolve the question. The constraint from [1] stands unchanged — the same
infrastructure delivers MacSync too — and header names emitted by a builder tell you which
*builder*, not which family the builder was sold to. Confidence moves up within the band,
not out of it.

**Recorded as: AMOS lineage, assessed, medium-high confidence.** The sample has been
submitted to MalwareBazaar; the family field in ThreatFox stays `unknown` until an
independent verdict exists. Guessing here would put an unverified family name into
machine-readable feeds, which is the failure mode this repository exists to avoid.

## Front-end difference worth flagging

Microsoft's cluster uses mass-registered look-alike domains on a `file<word><word>`
generator, fronted by a JavaScript fingerprinting gate. This case used a **compromised
legitimate website** and a **server-side single-use token gate** instead. Same back-end
shape, different acquisition strategy for the front end.

If that is one operation rather than two, compromised sites are being used alongside
registered ones — which matters for hunting, because a domain-generation pattern will
never surface the compromised half. It also means victim-side monitoring and
infrastructure-side monitoring are not substitutes for each other.

## Detection added from this analysis

- `detection/yara/clickfix_macos_stage3_loader.yar` — loader family by import
  combination and ad-hoc signature pattern, plus known-sample hashes. Unlike the other
  YARA rules here, this one **is** for Mach-O scanning.
- `detection/sigma/clickfix_stage3_dropper.yml` — the `curl` → `xattr` → `chmod +x`
  sequence under an interactive shell parent, plus proxy rules for the endpoints.
- `detection/suricata/clickfix_dante_c2.rules` — the `user`/`BuildID` header pair, the
  paste beacon, the `/curl/<hex>` fetch, and the stage-3 path.

---

See [REFERENCES.md](REFERENCES.md) for the full source list and how each claim maps to it.

---

## Verification

Every figure above was re-derived from the sample rather than carried over from notes.
The sample was never executed; it was decompressed to a non-executable copy and read with
`shasum`, `lipo`, `nm`, `otool` and `codesign`.

| Claim | Result |
|---|---|
| SHA-256 universal / arm64 / x86_64 | all three match |
| MD5, size 297,968 | match |
| Universal Mach-O, x86_64 + arm64 | confirmed |
| Imports | **16**, identical set in both slices |
| Linked libraries | `libSystem.B.dylib`, `libc++.1.dylib` — nothing else |
| Ad-hoc signature, no team ID | confirmed; identifier `setup-55554944a08118672974339184d0f77696ba1da6` |
| `__TEXT,__text` | 20,820 bytes |
| Encrypted blob | 69,632 bytes, entropy 7.9972, all 256 byte values present |
| YARA rules in `detection/yara/` | both match the universal binary and both slices |

Two corrections were made against the first draft of this analysis:

- The import count was stated as seventeen. It is **sixteen** — and the list in the draft
  already contained sixteen entries, so the prose was simply counting wrong.
- The encrypted blob was placed in `__DATA_CONST,__const`. It is in **`__DATA,__const`**.
  `__DATA_CONST` exists in this binary but holds only a 14-byte `__cstring` section.

Not verified here, and marked as such: the HMAC-based string decryption routine at
`+0x36d4`. That reading comes from disassembly which has not been independently repeated.
