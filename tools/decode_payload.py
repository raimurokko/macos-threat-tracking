#!/usr/bin/env python3
"""
Dekodiert einen ClickFix-Clipboard-Payload und gibt die Bestandteile aus.

Führt NICHTS aus. Kein subprocess, kein eval, kein os.system. Der Payload wird
ausschließlich als Text behandelt.

    python3 decode_payload.py clipboard.txt
    pbpaste | python3 decode_payload.py -
"""

import base64
import binascii
import json
import re
import sys

B64_RE = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")
URL_RE = re.compile(rb"https?://[^\s'\"\\)]+")
TOKEN_RE = re.compile(rb"\b[0-9a-f]{32,64}\b")


def try_b64(blob: bytes):
    """Dekodiert, wenn das Ergebnis wie Text aussieht. Sonst None."""
    for candidate in (blob, blob + b"=", blob + b"=="):
        try:
            out = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not out:
            continue
        printable = sum(1 for b in out if 9 <= b <= 13 or 32 <= b <= 126)
        if printable / len(out) > 0.85:
            return out
    return None


def peel(data: bytes, depth: int = 0, max_depth: int = 6, seen=None):
    """Schält rekursiv Base64-Schichten ab und sammelt jede Ebene ein."""
    if seen is None:
        seen = set()
    layers = []
    if depth >= max_depth:
        return layers
    for m in B64_RE.finditer(data):
        blob = m.group(0)
        if blob in seen:
            continue
        seen.add(blob)
        out = try_b64(blob)
        if out is None:
            continue
        layers.append({"depth": depth + 1, "encoded": blob.decode(), "decoded": out})
        layers.extend(peel(out, depth + 1, max_depth, seen))
    return layers


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    src = sys.argv[1]
    raw = sys.stdin.buffer.read() if src == "-" else open(src, "rb").read()

    layers = peel(raw)

    urls, tokens = [], []
    for chunk in [raw] + [l["decoded"] for l in layers]:
        urls += [u.decode() for u in URL_RE.findall(chunk)]
        tokens += [t.decode() for t in TOKEN_RE.findall(chunk)]

    urls = list(dict.fromkeys(urls))
    tokens = list(dict.fromkeys(tokens))

    print("=" * 72)
    print(f"Eingabe: {len(raw)} Bytes, {len(layers)} dekodierte Base64-Schicht(en)")
    print("=" * 72)

    for l in layers:
        print(f"\n--- Schicht {l['depth']} " + "-" * 56)
        try:
            print(l["decoded"].decode("utf-8", "replace").strip())
        except Exception:
            print(repr(l["decoded"][:400]))

    print("\n" + "=" * 72)
    print("URLs")
    print("=" * 72)
    gate = stage2 = None
    for u in urls:
        role = ""
        if "/p/" in u or u.startswith("http://"):
            role, gate = "  <- vermutlich Gate (Stage 1)", gate or u
        elif "/curl/" in u or u.startswith("https://"):
            role, stage2 = "  <- vermutlich Stage 2", stage2 or u
        print(f"  {u}{role}")

    if tokens:
        print("\nHex-Tokens")
        for t in tokens:
            print(f"  {t}")

    # Warnung bei ausführungsrelevanten Mustern
    danger = [p for p in (b"| zsh", b"|zsh", b"| bash", b"| sh", b"eval ")
              if any(p in c for c in [raw] + [l["decoded"] for l in layers])]
    if danger:
        print("\n" + "!" * 72)
        print("Ausführungsmuster gefunden: " + ", ".join(d.decode() for d in danger))
        print("Diese Zeilen NICHT in eine Shell einfügen.")
        print("!" * 72)

    out = {"urls": urls, "tokens": tokens, "gate": gate, "stage2": stage2,
           "layers": [{"depth": l["depth"],
                       "decoded": l["decoded"].decode("utf-8", "replace")}
                      for l in layers]}
    with open("decoded.json", "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print("\nGeschrieben: decoded.json")

    if gate and stage2:
        print("\nNächster Schritt:")
        print(f"  ./capture_stage2.sh --gate-url '{gate}' --stage2-url '{stage2}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
