#!/usr/bin/env python3
"""
Build a campaign's STIX 2.1 bundle from its iocs.csv.

    python3 tools/build_stix.py campaigns/2026-08-04-cloudflare-clickfix

Why this exists: the bundle drifted. On 2026-08-07 it held 9 indicators against 46
rows in the CSV — it had been updated by hand twice and then not again, which makes it
worse than useless for anyone importing it, because it looks complete.

Two rules this follows:

  * **Existing indicator IDs are preserved.** They are matched by STIX pattern against
    the current bundle and carried over untouched. Anyone who already ingested this
    bundle keeps their object identity. New indicators get deterministic UUIDv5 IDs
    derived from the pattern, so re-running produces byte-identical output.

  * **Nothing is dropped silently.** A CSV row whose type has no pattern mapping is
    reported on stderr and counted. Silent truncation in a feed is the failure mode
    this repository exists to avoid.
"""

import argparse
import csv
import json
import pathlib
import re
import sys
import uuid

NS = uuid.UUID("7c2b3a1e-5f4d-4c8b-9a6e-1d3f5b7c9e11")   # this repo's namespace
IDENTITY = "identity--743549b0-8df5-487c-9f3b-b93228647e4a"
ATTACK_PATTERN = "attack-pattern--5e700096-6c66-4730-8db7-a348dbb768a1"
MALWARE = "malware--" + str(uuid.uuid5(NS, "malware:osx.amos"))


def esc(v):
    """Escape a value for a STIX string literal."""
    return v.replace("\\", "\\\\").replace("'", "\\'")


def rx(v):
    """Escape a value for use inside a STIX MATCHES regex."""
    return re.escape(v).replace("\\", "\\\\").replace("'", "\\'")


# Behaviour rows in iocs.csv are human-readable shorthand with placeholders
# (<url>, <base64>), not literals. Escaping them yields a regex that can never
# match. These curated patterns are the operative form and are carried over
# verbatim from the hand-written bundle, which also preserves their object IDs.
BEHAVIOUR_PATTERNS = {
    "eval \"$(printf '%s' '<base64>' | base64 -d)\"":
        r"""[process:command_line MATCHES 'eval \\"\\$\\(printf .{0,40}base64 -d\\)\\"']""",
    "curl -s <url> | zsh":
        r"""[process:command_line MATCHES 'curl -s .{0,200}\\| ?zsh']""",
    "openssl base64 -d -A":
        r"""[process:command_line MATCHES 'openssl base64 -d -A']""",
}


def pattern_for(t, value):
    """Map an iocs.csv (type, value) pair to a STIX 2.1 pattern, or None."""
    if t == "domain":
        return f"[domain-name:value = '{esc(value)}']"
    if t == "url":
        return f"[url:value = '{esc(value)}']"
    if t == "ip-dst":
        return f"[ipv4-addr:value = '{esc(value)}']"
    if t == "sha256":
        return f"[file:hashes.'SHA-256' = '{esc(value)}']"
    if t == "md5":
        return f"[file:hashes.MD5 = '{esc(value)}']"
    if t == "asn":
        n = value.upper().lstrip("AS")
        return f"[autonomous-system:number = {int(n)}]" if n.isdigit() else None
    if t == "http-header":
        name = value.split(" ")[0]
        return ("[network-traffic:extensions.'http-request-ext'"
                f".request_header.'{esc(name)}' LIKE '%']")
    if t == "path":
        v = value.replace("~", "")
        if v.startswith("/zxc/"):
            # URL path on the operator's server, not a location on the host
            return f"[url:value MATCHES '{rx(v)}$']"
        if v.endswith("/"):
            return f"[directory:path MATCHES '{rx(v.rstrip('/'))}$']"
        name, _, parent = v.rsplit("/", 1)[1], None, v.rsplit("/", 1)[0]
        return (f"[file:name = '{esc(name)}' AND "
                f"file:parent_directory_ref.path = '{esc(parent)}']")
    if t in ("string", "token"):
        return f"[artifact:payload_bin MATCHES '{rx(value)}']"
    if t == "behaviour":
        return BEHAVIOUR_PATTERNS.get(value)
    if t == "pattern":
        return f"[file:name MATCHES '{value}']"     # already a regex in the CSV
    return None


PHASE = {
    "c2-gating": "command-and-control", "c2-gating-origin": "command-and-control",
    "c2": "command-and-control", "telemetry": "command-and-control",
    "payload-host": "delivery", "payload-path": "delivery",
    "payload": "installation", "exfiltration": "actions-on-objectives",
    "persistence": "installation", "staging": "actions-on-objectives",
    "execution": "exploitation", "obfuscation": "defense-evasion",
    "clipboard-marker": "exploitation", "campaign-marker": "delivery",
    "victim-token": "exploitation", "payload-token": "delivery",
    "signing-identifier": "defense-evasion", "hosting": "command-and-control",
    "header-name": "command-and-control", "embedded-token": "command-and-control",
}
# Roles whose indicators point at the malware family as well as the technique
FAMILY_ROLES = {"payload", "payload-path", "persistence", "exfiltration",
                "staging", "embedded-token", "c2"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("campaign", help="campaign directory containing iocs.csv")
    a = ap.parse_args()

    base = pathlib.Path(a.campaign)
    rows = list(csv.DictReader(open(base / "iocs.csv")))
    old = json.load(open(base / "iocs.stix.json"))

    keep = {o["type"]: o for o in old["objects"] if o["type"] in ("identity", "attack-pattern")}
    by_pattern = {o["pattern"]: o for o in old["objects"] if o["type"] == "indicator"}

    objects = [keep["identity"], keep["attack-pattern"], {
        "type": "malware", "spec_version": "2.1", "id": MALWARE,
        "created": "2026-08-07T00:00:00.000Z", "modified": "2026-08-07T00:00:00.000Z",
        "created_by_ref": IDENTITY,
        "name": "AMOS (Atomic macOS Stealer)",
        "description": ("Commercially rented macOS infostealer. Confirmed for this "
                        "campaign on 2026-08-07 after the stage-3 payload was decrypted: "
                        "the app.zip/apptwo.zip/appex.zip archive triple under a /zxc/ "
                        "path, the user/BuildID/cl/cn header set, FileGrabber/ and the "
                        ".logged marker all match independently published analyses. "
                        "Beyond credential theft it installs root LaunchDaemons and "
                        "replaces Ledger, Trezor and Exodus with attacker-supplied builds."),
        "malware_types": ["spyware", "trojan"], "is_family": True,
        # implementation-language-ov; no standard property carries "macOS", and a
        # custom x_ property makes the bundle fail strict validation, so the
        # platform is stated in the description instead.
        "implementation_languages": ["c", "applescript"],
    }]

    rels, reused, added, skipped = [], 0, 0, []
    for r in rows:
        pat = pattern_for(r["type"], r["value"])
        if not pat:
            skipped.append(f'{r["type"]}: {r["value"][:60]}')
            continue
        if pat in by_pattern:
            ind = by_pattern[pat]
            reused += 1
        else:
            ts = f'{r["first_seen"]}T00:00:00.000Z'
            ind = {
                "type": "indicator", "spec_version": "2.1",
                "id": "indicator--" + str(uuid.uuid5(NS, pat)),
                "created": ts, "modified": ts, "created_by_ref": IDENTITY,
                "name": f'{r["role"]}: {r["value"][:80]}',
                "description": r["notes"],
                "indicator_types": ["malicious-activity"]
                if r["type"] not in ("behaviour", "string", "pattern")
                else ["anomalous-activity"],
                "pattern_type": "stix", "pattern": pat, "valid_from": ts,
                "confidence": {"high": 85, "medium": 50, "low": 15}.get(r["confidence"], 50),
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                                       "phase_name": PHASE.get(r["role"], "delivery")}],
            }
            added += 1
        objects.append(ind)

        for target in [ATTACK_PATTERN] + ([MALWARE] if r["role"] in FAMILY_ROLES else []):
            rels.append({
                "type": "relationship", "spec_version": "2.1",
                "id": "relationship--" + str(uuid.uuid5(NS, ind["id"] + target)),
                "created": ind["created"], "modified": ind["modified"],
                "relationship_type": "indicates",
                "source_ref": ind["id"], "target_ref": target,
            })

    objects.extend(rels)
    bundle = {"type": "bundle", "id": old["id"], "objects": objects}
    (base / "iocs.stix.json").write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n")

    print(f"  {len(rows)} CSV rows -> {reused + added} indicators "
          f"({reused} existing IDs preserved, {added} new), {len(rels)} relationships")
    if skipped:
        print(f"  {len(skipped)} rows had no pattern mapping and were NOT included:",
              file=sys.stderr)
        for s in skipped:
            print(f"    - {s}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
