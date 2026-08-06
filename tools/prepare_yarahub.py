#!/usr/bin/env python3
"""
Erzeugt YARAhub-taugliche Kopien der Regeln.

YARAhub verlangt Pflichtfelder, die eine Regel im Repo nicht braucht - vor allem
yarahub_reference_md5, die MD5 einer Datei, auf die die Regel matcht. Dieses Skript
nimmt die Referenzdatei, prueft dass die Regel darauf wirklich anschlaegt, und
schreibt eine angereicherte Kopie nach detection/yara/yarahub/.

    python3 prepare_yarahub.py --sample /pfad/clipboard_payload.txt \
                               --rule detection/yara/clickfix_campaign_2026_08_04.yar

Ohne --rule werden alle Regeln verarbeitet, die auf das Sample matchen.

Die UUID wird deterministisch aus dem Regelnamen abgeleitet: Wiederholte Laeufe
liefern dieselbe UUID, damit ein spaeteres Update dieselbe Regel aktualisiert statt
eine zweite anzulegen.
"""

import argparse
import hashlib
import pathlib
import re
import sys
import uuid

NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # RFC 4122 DNS namespace

# Bewusste Abweichung: YARAhub nennt "UUID 4 format", wir erzeugen UUIDv5. Ein echtes v4
# waere zufaellig - jeder erneute Lauf erzeugte eine neue UUID und damit bei YARAhub eine
# Dublette statt eines Updates. Die Ableitung aus dem Regelnamen macht Wiederholungen
# idempotent. Bisher wurde das akzeptiert; falls YARAhub die Version je streng prueft,
# ist das hier die Stelle, an der es bricht.

DEFAULTS = {
    "yarahub_license": "CC0 1.0",
    "yarahub_rule_matching_tlp": "TLP:WHITE",
    "yarahub_rule_sharing_tlp": "TLP:WHITE",
    "yarahub_author_email": "",
    "yarahub_reference_link": "https://github.com/raimurokko/macos-threat-tracking",
}

RULE_NAME_RE = re.compile(r"^rule\s+(\w+)", re.M)


def rule_name(text: str) -> str:
    m = RULE_NAME_RE.search(text)
    if not m:
        raise ValueError("Kein 'rule <name>' gefunden")
    return m.group(1)


def enrich(text: str, md5: str, link: str, email: str) -> str:
    name = rule_name(text)
    if "yarahub_uuid" in text:
        print(f"  bereits angereichert, wird uebersprungen: {name}")
        return text

    ruid = str(uuid.uuid5(NAMESPACE, f"novum-analytica/{name}"))
    fields = [
        ("yarahub_uuid", ruid),
        ("yarahub_reference_md5", md5),
        ("yarahub_reference_link", link),
        ("yarahub_license", DEFAULTS["yarahub_license"]),
        ("yarahub_rule_matching_tlp", DEFAULTS["yarahub_rule_matching_tlp"]),
        ("yarahub_rule_sharing_tlp", DEFAULTS["yarahub_rule_sharing_tlp"]),
    ]
    if email:
        fields.insert(2, ("yarahub_author_email", email))

    block = "".join(f'        {k:<28}= "{v}"\n' for k, v in fields)

    # direkt nach der date-Zeile einfuegen; date ist bei YARAhub ebenfalls Pflicht
    m = re.search(r"^([ \t]*date\s*=\s*\"[^\"]+\"\s*\n)", text, re.M)
    if not m:
        raise ValueError(f"{name}: Pflichtfeld 'date' fehlt in der meta-Sektion")
    return text[: m.end(1)] + block + text[m.end(1):]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True,
                    help="Datei, auf die die Regel matcht (wird bei YARAify hochgeladen)")
    ap.add_argument("--rule", action="append",
                    help="Einzelne Regeldatei; mehrfach nutzbar. Default: alle")
    ap.add_argument("--yara-dir", default="detection/yara")
    ap.add_argument("--out", default="detection/yara/yarahub")
    ap.add_argument("--link", default=DEFAULTS["yarahub_reference_link"])
    ap.add_argument("--email", default="")
    a = ap.parse_args()

    sample = pathlib.Path(a.sample)
    if not sample.is_file():
        print(f"Sample nicht gefunden: {sample}", file=sys.stderr)
        return 2

    raw = sample.read_bytes()
    md5 = hashlib.md5(raw).hexdigest()
    sha256 = hashlib.sha256(raw).hexdigest()
    print(f"Referenzdatei : {sample}  ({len(raw)} Bytes)")
    print(f"MD5           : {md5}")
    print(f"SHA256        : {sha256}\n")

    ydir = pathlib.Path(a.yara_dir)
    rules = ([pathlib.Path(r) for r in a.rule] if a.rule
             else sorted(p for p in ydir.glob("*.yar") if p.name != "index.yar"))

    try:
        import yara
    except ImportError:
        print("Hinweis: yara-python nicht installiert, Match-Pruefung entfaellt.\n")
        yara = None

    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    written = skipped = 0

    for rp in rules:
        text = rp.read_text(encoding="ascii")
        name = rule_name(text)

        if yara:
            try:
                if not yara.compile(filepath=str(rp)).match(data=raw):
                    print(f"  UEBERSPRUNGEN  {name}")
                    print("                 matcht die Referenzdatei nicht.")
                    print("                 YARAhub wuerde die Regel ablehnen.\n")
                    skipped += 1
                    continue
            except yara.Error as e:
                print(f"  FEHLER         {name}: {e}\n")
                skipped += 1
                continue

        enriched = enrich(text, md5, a.link, a.email)
        dst = out / rp.name
        dst.write_text(enriched, encoding="ascii")

        if any(ord(c) > 127 for c in enriched):
            print(f"  WARNUNG        {dst} enthaelt Non-ASCII. YARAhub lehnt das ab.")
        print(f"  geschrieben    {dst.resolve()}  ({name})")
        written += 1

    print(f"\n{written} Regel(n) bereit, {skipped} uebersprungen.")
    if written:
        print(f"\nHochzuladen sind die Dateien in {out.resolve()} -")
        print("die gleichnamigen unter detection/yara/ haben die Pflichtfelder NICHT.")
        print(f"\nNaechster Schritt: '{sample.name}' bei YARAify hochladen,")
        print(f"dann die Datei(en) aus {out}/ bei YARAhub einreichen.")
        print("Die MD5 im meta-Feld muss zu der hochgeladenen Datei passen.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
