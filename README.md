# macos-threat-tracking

Tracking of macOS ClickFix campaigns: vetted IOCs, decoded delivery chains, YARA and
Sigma detections, and tooling for capturing payloads without executing them.

Maintained by **[Novum Analytica GmbH](https://novumanalytica.com)**, Berlin.
Everything here is published **TLP:CLEAR** — use it, fork it, feed it into your stack.

---

## Why this exists

ClickFix works because the victim runs the malware themselves. A fake verification
overlay writes a command to the clipboard and talks the user through pasting it into
Terminal. No download, no attachment, no signed binary — and therefore very little for
Gatekeeper, XProtect or a browser download filter to catch.

The macOS side of this is under-documented compared to the Windows/PowerShell variant.
This repository tracks what we run into, with enough detail that the indicators are
actually usable rather than just listed.

## Layout

```
campaigns/<date>-<short-name>/   one directory per campaign
    writeup.md                   chain, analysis, caveats
    iocs.csv                     campaign indicators
    iocs.stix.json               STIX 2.1 bundle (MISP / OpenCTI import)
    payload_analysis.md          stage-2 and stage-3 analysis, where recovered
    stage4_payload.md            the decrypted payload, where the blob was broken
    REFERENCES.md                sources, with what each supports and constrains
    samples/                     text artefacts only, never binaries
detection/
    yara/                        file, clipboard-dump, shell-history and Mach-O rules
    sigma/                       process_creation (macOS), dns_query, proxy
    suricata/                    network rules for stage-2 and stage-4 C2
tools/                           safe capture and static triage toolkit
    freshfix/                    emulation-based recovery of the stage-3 payload
iocs/all.csv                     aggregated feed across campaigns, with status column
```

## Campaigns

| Date | Name | Delivery | Family | Status |
|---|---|---|---|---|
| 2026-08-04 | [Fake Cloudflare Turnstile](campaigns/2026-08-04-cloudflare-clickfix/writeup.md) | compromised DE school site | AMOS, **confirmed** | active |

The family field read *assessed* until 2026-08-07 and the machine-readable feeds kept it
at `unknown`, because the evidence was chain shape only and one vendor reports the same
infrastructure also delivering MacSync. See
[REFERENCES.md](campaigns/2026-08-04-cloudflare-clickfix/REFERENCES.md) for how each claim
maps to a source, including the ones that constrain it.

**Update 2026-08-07 — the payload is no longer encrypted, and the family is settled.** The
stage-3 blob was broken by emulating the loader's own key derivation; see
[stage4_payload.md](campaigns/2026-08-04-cloudflare-clickfix/stage4_payload.md).

The payload matches independently published AMOS analyses on details that coincidence does
not produce — the `app.zip` / `apptwo.zip` / `appex.zip` archive triple, the `/zxc/` path
segment, the `user` / `BuildID` / `cl` / `cn` header set, `FileGrabber/` and the `.logged`
marker. **AMOS, confirmed.**

It also raised the severity. Besides stealing browser, wallet and cloud credentials, the
payload installs **two root LaunchDaemons** disguised as Apple services and **replaces
Ledger, Trezor and Exodus with attacker-supplied builds**. Neither behaviour is new — both
were published in November 2025 — but both change what you tell a victim. If you are
triaging a host that ran this chain, treat it as a root compromise rather than a data
breach, and check the four persistence paths in that file first.

What is new here is the packer: `freshfix`, its key schedule, and the analyst-tool
blacklist that only exists at runtime. §6 of that file separates the two carefully,
because the first draft did not.

## Detection

`detection/yara/` — one rule per file, plus `index.yar` as an aggregate include:

| File | Rule | Use |
|---|---|---|
| `clickfix_campaign_2026_08_04.yar` | campaign infrastructure and clipboard markers | alert directly |
| `clickfix_macos_generic_exec.yar` | ClickFix execution shape (decode + pipe to shell) | hunting and triage |
| `clickfix_fake_captcha_page.yar` | the lure page itself (clipboard write + Terminal instructions) | scan web root, CMS templates, DB dumps |
| `clickfix_macos_stage3_loader.yar` | the stage-3 loader stub, by import combination and ad-hoc signature | **Mach-O scanning** |
| `clickfix_macos_stage3_known_samples.yar` | known stage-3 hashes | **Mach-O scanning** |
| `freshfix_payload_internals.yar` | packer key-schedule constants, the decrypted payload, and the runtime analyst-tool blacklist | **Mach-O, plaintext payload, and memory** |

```sh
yara detection/yara/index.yar /path/to/scan
```

The first three are intended for shell history, clipboard dumps, browser cache, HTML
artefacts and memory — **not** for Mach-O scanning. The two `stage3` rules are the
exception: they **are** for Mach-O, and running them over text only wastes cycles.

The generic rule requires a decode step *and* a pipe, which keeps common developer
one-liners out: `curl … | sh` from a rustup-style installer does not fire it. The loader
rule is the one to watch when tuning — it is defined partly by imports the binary
*lacks*, so a variant that links `CFNetwork` or Security.framework will slip past it
without a sound. Still worth tuning all of them against your own estate before you page
anyone.

One rule in `freshfix_payload_internals.yar` is **memory-scan only** and says so in its
metadata. The analyst-tool blacklist it matches is XOR-encrypted per fragment inside the
Mach-O and only assembles at runtime, so a file scan can never hit it. Point it at a live
process or a core dump, not at disk.

`detection/suricata/` — network rules keyed on the non-standard request headers this
family emits. The rules match on the header *names*, not the observed values: the values
were seen once, and one observation does not establish that a value survives a rebuild.
Stage 2 sends `user` and `BuildID`; the decrypted stage-4 payload adds `cl`, `cn` and
`X-Partial`, which is what rules 9000105–9000109 cover.

`detection/sigma/` — process creation on macOS, plus DNS and proxy rules for the known
infrastructure. The behavioural rule needs tuning before you alert on it: `curl | sh` is
common enough in developer workflows to drown you in noise. A Homebrew/git-hooks filter
is included as a starting point, not as a finished answer. The two `stage4` rules are the
opposite case — root LaunchDaemons with forged Apple labels and wallet bundles replaced
via `sudo -S` have no benign equivalent, and are set to `critical` accordingly.

## Tools

`tools/` holds a capture setup for retrieving a second stage **without ever letting a
shell see it**. The rule the whole thing rests on: there is no pipe into `sh`, `zsh` or
`bash` anywhere in these scripts. Payloads are fetched with `curl -o`, immediately
`chmod 000`'d, hashed, and recorded with provenance.

- `RUNBOOK.md` — VM isolation, mitmproxy, the exact order of operations
- `decode_payload.py` — peels the base64 layers off a clipboard payload, static only
- `capture_stage2.sh` — gate check, then fetch-to-file; aborts if the gate declines
- `triage_payload.sh` — read-only static triage
- `mitm_addon.py` — records lure pages and auto-extracts clipboard payloads
- `freshfix/` — recovers the stage-3 payload by **emulating** the loader rather than
  running it: Unicorn interprets the instructions, every libSystem call is serviced in
  Python, and the emulator has no filesystem, network or syscall access. Three steps,
  reproducible from the public sample alone. See
  [`tools/freshfix/README.md`](tools/freshfix/README.md).
- `grab_lure.sh` — fetches a lure page plus its external scripts; flags clipboard markers
- `watch_clickfix.sh` — polls urlscan for new ClickFix submissions; capture is opt-in

On timing: ClickFix lures are gated and short-lived. On 2026-08-04 a batch was already
dead roughly 70 minutes after submission, and urlscan's own scanner had been gated out too — so
the archived DOM was no help either. `watch_clickfix.sh` exists to shorten that gap, but
the reliable reference sample is the injected block recovered from a site you already
have an incident relationship with. See
[cluster_expansion.md](campaigns/2026-08-04-cloudflare-clickfix/cluster_expansion.md).

See [DISCLAIMER.md](DISCLAIMER.md) before using any of it.

## Using the IOCs

`iocs/all.csv` carries a `status` column (`active` / `sinkholed` / `down` / `expired`).
Indicators are not removed when they go dead — retrospective hunting needs them. Filter
on status if you are building a blocklist.

**Lure domains are victims.** Compromised sites appear in the writeups for context and
are deliberately kept out of the indicator files. Blocking them punishes the site's own
users and creates a delisting problem for people who did nothing wrong.

## Contributing

Issues and PRs welcome, particularly: additional campaign infrastructure, corrections,
false positives on the detection rules, and payload analysis where we only have
`unknown`. If you can attribute a family we left open, that is the single most useful
thing you can contribute.

Please do not open issues asking for samples.

## Licence

Detections and IOCs: CC0. Tooling: MIT. Attribution appreciated but not required.
