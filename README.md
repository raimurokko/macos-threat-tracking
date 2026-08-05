# macos-threat-tracking

Tracking of macOS ClickFix campaigns: vetted IOCs, decoded delivery chains, YARA and
Sigma detections, and tooling for capturing payloads without executing them.

Maintained by **[Novum Analytica GmbH](https://novum-analytica.de)**, Berlin.
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
detection/
    yara/                        file, clipboard-dump and shell-history rules
    sigma/                       process_creation (macOS), dns_query, proxy
tools/                           safe capture and static triage toolkit
iocs/all.csv                     aggregated feed across campaigns, with status column
```

## Campaigns

| Date | Name | Delivery | Family | Status |
|---|---|---|---|---|
| 2026-08-04 | [Fake Cloudflare Turnstile](campaigns/2026-08-04-cloudflare-clickfix/writeup.md) | compromised DE school site | unknown | active |

## Detection

`detection/yara/` — one rule per file, plus `index.yar` as an aggregate include:

| File | Rule | Use |
|---|---|---|
| `clickfix_campaign_2026_08_04.yar` | campaign infrastructure and clipboard markers | alert directly |
| `clickfix_macos_generic_exec.yar` | ClickFix execution shape (decode + pipe to shell) | hunting and triage |
| `clickfix_fake_captcha_page.yar` | the lure page itself (clipboard write + Terminal instructions) | scan web root, CMS templates, DB dumps |

```sh
yara detection/yara/index.yar /path/to/scan
```

Intended for shell history, clipboard dumps, browser cache, HTML artefacts and memory —
**not** for Mach-O scanning. The generic rule requires a decode step *and* a pipe, which
keeps common developer one-liners out: `curl … | sh` from a rustup-style installer does
not fire it. Still worth tuning against your own estate before you page anyone.

`detection/sigma/` — process creation on macOS, plus DNS and proxy rules for the known
infrastructure. The behavioural rule needs tuning before you alert on it: `curl | sh` is
common enough in developer workflows to drown you in noise. A Homebrew/git-hooks filter
is included as a starting point, not as a finished answer.

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
- `grab_lure.sh` — fetches a lure page plus its external scripts; flags clipboard markers
- `watch_clickfix.sh` — polls urlscan for new ClickFix submissions; capture is opt-in

On timing: ClickFix lures are gated and short-lived. On 2026-08-04 a batch was already
dead 78 minutes after submission, and urlscan's own scanner had been gated out too — so
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
