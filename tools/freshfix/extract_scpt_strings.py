#!/usr/bin/env python3
"""
Extract the literal string table from the decrypted FasdUAS AppleScript.

Literals are stored as a big-endian u16 byte-length followed by UTF-16BE data.
A naive byte scan mistakes the low half of the length word for a leading
character, so parse the length properly and validate the decode.

    uv run python extract_scpt_strings.py [--shell]
"""

import argparse
import pathlib
import sys

# Markers that make a literal interesting as a command rather than a path
SHELL_HINTS = ("curl", "sudo", "ditto", "chmod", "chown", "launchctl", "pkill",
               "rm ", "mkdir", "security ", "dscl", "system_profiler", "sw_vers",
               "uname", "defaults read", "xattr", "nohup", "stat -f", "echo ",
               "cp -f", "file -b", "#!/bin/bash", "while true", "osascript")


def literals(d):
    """Yield (offset, text) for every well-formed UTF-16BE literal."""
    out, i, n = [], 0, len(d)
    while i + 2 < n:
        ln = (d[i] << 8) | d[i + 1]
        if ln >= 6 and ln % 2 == 0 and i + 2 + ln <= n:
            raw = d[i + 2:i + 2 + ln]
            if all(raw[k] == 0 and (0x20 <= raw[k + 1] < 0x7F or raw[k + 1] in (9, 10, 13))
                   for k in range(0, ln, 2)):
                txt = raw.decode("utf-16-be")
                out.append((i, txt))
                i += 2 + ln
                continue
        i += 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shell", action="store_true",
                    help="only literals that look like shell commands")
    ap.add_argument("--min", type=int, default=3)
    ap.add_argument("payload", nargs="?", default="payload_decrypted.bin",
                    help="decrypted payload (default: %(default)s)")
    a = ap.parse_args()

    src = pathlib.Path(a.payload)
    d = src.read_bytes()
    lits = literals(d)
    print(f"# {len(lits)} literals from {src.name} ({len(d)} bytes)\n")
    for off, t in lits:
        if len(t) < a.min:
            continue
        if a.shell and not any(h in t for h in SHELL_HINTS):
            continue
        shown = t.replace("\n", "\\n")
        print(f"{off:#07x}  {shown}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
