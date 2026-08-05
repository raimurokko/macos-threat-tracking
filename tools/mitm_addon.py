"""
mitmproxy-Addon fuer ClickFix-Analyse.

Zweck:
  1. Jede Antwort mitschreiben (die Lure-Seite und ihr injiziertes Script sind
     fuer den Betreiber der Website oft wichtiger als der Payload selbst).
  2. Clipboard-Schreibzugriffe im JavaScript erkennen und melden.
  3. Base64-Blobs aus Seiteninhalten ziehen, damit du das Token bekommst,
     ohne die Zwischenablage anfassen zu muessen.

Fuehrt nichts aus. Dekodiert nur und schreibt Text auf Platte.

    mitmdump -s mitm_addon.py -w flows.flow --listen-port 8080
"""

import base64
import binascii
import hashlib
import pathlib
import re
import time

from mitmproxy import http, ctx

OUTDIR = pathlib.Path.home() / "lab" / "artifacts"

CLIP_RE = re.compile(
    rb"navigator\.clipboard\.writeText|execCommand\s*\(\s*['\"]copy|"
    rb"ClipboardItem|document\.execCommand",
    re.I,
)
INSTR_RE = re.compile(
    rb"Menschliche Verifizierung|human verification|verify you are|"
    b"Terminal|Command\\s*\\+\\s*Space|\xe2\x8c\x98|Ausf\xc3\xbchren|Win\\s*\\+\\s*R",
    re.I,
)
B64_RE = re.compile(rb"[A-Za-z0-9+/]{60,}={0,2}")
INTEREST = ("text/html", "javascript", "application/json", "text/plain")


class ClickFixWatch:
    def __init__(self):
        OUTDIR.mkdir(parents=True, exist_ok=True)
        self.n = 0

    def _save(self, tag: str, host: str, data: bytes) -> pathlib.Path:
        h = hashlib.sha256(data).hexdigest()[:12]
        safe = re.sub(r"[^A-Za-z0-9.-]", "_", host)[:60]
        p = OUTDIR / f"{tag}_{safe}_{h}.txt"
        p.write_bytes(data)
        return p

    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return
        ctype = flow.response.headers.get("content-type", "")
        if not any(t in ctype for t in INTEREST):
            return

        body = flow.response.content or b""
        if not body:
            return

        self.n += 1
        host = flow.request.pretty_host
        hits = []

        if CLIP_RE.search(body):
            hits.append("clipboard-write")
        if INSTR_RE.search(body):
            hits.append("clickfix-instructions")

        if hits:
            p = self._save("lure", host, body)
            ctx.log.warn(f"[ClickFix] {'+'.join(hits)} @ {flow.request.pretty_url}")
            ctx.log.warn(f"[ClickFix] gespeichert: {p}")

            for m in B64_RE.finditer(body):
                blob = m.group(0)
                for cand in (blob, blob + b"=", blob + b"=="):
                    try:
                        dec = base64.b64decode(cand, validate=True)
                    except (binascii.Error, ValueError):
                        continue
                    if not dec:
                        continue
                    printable = sum(1 for b in dec if 9 <= b <= 13 or 32 <= b <= 126)
                    if printable / len(dec) < 0.85:
                        continue
                    txt = dec.decode("utf-8", "replace")
                    ctx.log.warn(f"[ClickFix] Base64 dekodiert:\n{txt[:600]}")
                    self._save("decoded", host, dec)
                    for url in re.findall(rb"https?://[^\s'\"\\)]+", dec):
                        ctx.log.warn(f"[ClickFix]   URL: {url.decode()}")
                    break

    def done(self):
        ctx.log.info(f"[ClickFix] {self.n} relevante Antworten gesehen. "
                     f"Artefakte in {OUTDIR}")


addons = [ClickFixWatch()]
