# Disclaimer and scope

## Purpose

Defensive. Everything here exists so that defenders can detect, block and understand
macOS ClickFix activity. Nothing in this repository builds, packs, obfuscates or
delivers malware.

## No samples

This repository contains **no malware samples**, in any form — not archived, not
encoded, not "for research". Hashes are published; the files themselves belong on
[MalwareBazaar](https://bazaar.abuse.ch/). Requests for samples will be closed without
comment.

## The tooling does not execute anything

`tools/` retrieves payloads and renders them inert. There is no pipe into a shell
anywhere in it, by design. Fetched payloads are written to disk with `curl -o`,
immediately `chmod 000`'d, and triaged read-only.

If you modify these scripts and introduce such a pipe, you have removed the only thing
that made them safe. Do not run them outside an isolated, disposable VM.

## Attribution

We label a malware family only when we have analysed the payload. Where the second stage
was never retrieved, the family is recorded as `unknown` — even when the delivery chain
strongly resembles a known family.

This is deliberate. The macOS ClickFix loader is family-agnostic: `curl | zsh` looks
identical whether it lands AMOS, MacSync or SHub. A guess entered into a machine-readable
field propagates into other people's reporting as fact. If you can close one of these
gaps from the payload, please open an issue.

## Compromised infrastructure

Lure sites are usually legitimate websites that were compromised or abused. They are
named in writeups only where the operator has been notified and the issue resolved, and
they are **never** included in the indicator files.

Adding a compromised site to a blocklist blocks it for its own users and creates a
delisting burden for an operator who is already the victim. Where a compromised site
appears, it is marked `is_compromised` in the STIX bundle and flagged in the CSV notes.

## Responsible disclosure

Where a compromised site is identified, we notify the operator and — for German public
bodies — the relevant CERT and supervisory authority before publishing. Personal contact
data gathered in that process is never published here.

## Warranty

None. Detection rules may produce false positives; tune them against your own
environment before alerting. The capture tooling contacts live attacker infrastructure
and will expose your source address to the operator. You are responsible for what you
run and where you run it.

## Contact

Security and coordination matters: see the contact details on
[novumanalytica.com](https://novumanalytica.com). For everything else, open an issue.
