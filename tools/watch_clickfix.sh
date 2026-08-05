#!/usr/bin/env bash
#
# Beobachtet urlscan.io auf neu eingereichte ClickFix-Scans und zieht die Lure-Seite,
# solange sie noch ausgeliefert wird.
#
# Hintergrund: Am 2026-08-04 lagen zwischen ThreatFox-Einreichung und unserem Abruf
# 78 Minuten - da war die gesamte Infrastruktur bereits abgeraeumt oder gegated.
# urlscans eigener Scanner wurde ebenso ausgesperrt, ein API-Key haette nicht
# geholfen. Wer ein echtes Referenz-Sample will, muss frueher da sein.
#
# Der Suchlauf selbst ist passiv - reine urlscan-Abfrage, keine Angreifer-
# infrastruktur. Das Herunterladen der Lure passiert NUR mit --capture, weil es
# von deiner IP aus an aktive Angreiferinfrastruktur geht.
#
# Aufruf:
#   watch_clickfix.sh                      # nur melden, nichts abrufen
#   watch_clickfix.sh --capture            # neue Ziele sofort sichern
#   watch_clickfix.sh --capture --interval 120 --outdir ~/lures
#
set -euo pipefail

INTERVAL=300
CAPTURE=0
OUTDIR="clickfix_watch"
QUERY='task.tags:clickfix'
RULE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --capture)  CAPTURE=1; shift ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --outdir)   OUTDIR="$2"; shift 2 ;;
        --query)    QUERY="$2"; shift 2 ;;
        --rule)     RULE="$2"; shift 2 ;;
        -h|--help)  sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "Unbekannte Option: $1" >&2; exit 2 ;;
    esac
done

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRAB="$SELF/grab_lure.sh"
[[ $CAPTURE -eq 0 || -x "$GRAB" ]] || { echo "grab_lure.sh nicht gefunden/ausfuehrbar: $GRAB" >&2; exit 2; }
# Default-Regel nur setzen, wenn sie wirklich existiert - sonst bleibt yara aus.
if [[ -z "$RULE" && -f "$SELF/../detection/yara/clickfix_fake_captcha_page.yar" ]]; then
    RULE="$SELF/../detection/yara/clickfix_fake_captcha_page.yar"
fi

mkdir -p "$OUTDIR"
SEEN="$OUTDIR/.seen_uuids"
touch "$SEEN"

# Erster Lauf: bestehende Scans nur vormerken, nicht abrufen. Sonst wuerde der
# Watcher beim Start sofort ueber den gesamten Bestand herfallen - lauter alte,
# laengst tote Ziele, und ein unnoetig breiter Kontakt zur Angreiferinfrastruktur.
PRIMED=0
[[ -s "$SEEN" ]] && PRIMED=1

echo "Watcher laeuft. Query: $QUERY | Intervall: ${INTERVAL}s | Capture: $([[ $CAPTURE -eq 1 ]] && echo an || echo AUS)"
echo "Ausgabe: $OUTDIR   (Abbruch mit Strg-C)"
[[ $PRIMED -eq 0 ]] && echo "Erster Lauf: Bestand wird nur vorgemerkt, nichts abgerufen."
echo

trap 'echo; echo "Beendet. $(wc -l < "$SEEN" | tr -d " ") UUIDs vorgemerkt."; exit 0' INT TERM

while true; do
    ts="$(date -u +%H:%M:%SZ)"
    raw="$(curl -s --max-time 30 --get \
             --data-urlencode "q=$QUERY" --data-urlencode 'size=100' \
             'https://urlscan.io/api/v1/search/' || true)"

    if [[ -z "$raw" ]]; then
        echo "[$ts] urlscan nicht erreichbar, naechster Versuch in ${INTERVAL}s"
        sleep "$INTERVAL"; continue
    fi

    # uuid<TAB>url<TAB>zeit; leer bei Parse-Fehler oder Rate-Limit-Antwort
    new="$(printf '%s' "$raw" | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for x in d.get('results',[]):
    t=x.get('task',{})
    if t.get('uuid') and t.get('url'):
        print(t['uuid'], t['url'], t.get('time','')[:19], sep='\t')
" || true)"

    if [[ -z "$new" ]]; then
        echo "[$ts] keine verwertbare Antwort (Rate-Limit?)"
        sleep "$INTERVAL"; continue
    fi

    count=0
    while IFS=$'\t' read -r uuid url when; do
        [[ -n "$uuid" ]] || continue
        grep -qxF "$uuid" "$SEEN" && continue
        printf '%s\n' "$uuid" >> "$SEEN"
        count=$((count+1))

        if [[ $PRIMED -eq 0 ]]; then continue; fi

        echo "[$ts] NEU  $when  $url"

        if [[ $CAPTURE -eq 1 ]]; then
            slug="$(printf '%s' "$url" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-60)"
            dest="$OUTDIR/$(date -u +%Y%m%dT%H%M%SZ)_$slug"
            if "$GRAB" "$url" "$dest" >"$dest.log" 2>&1; then
                if grep -q 'TREFFER' "$dest.log"; then
                    echo "        >>> CLIPBOARD-MARKER in $dest"
                    grep 'TREFFER' "$dest.log" | sed 's/^/        /'
                    command -v osascript >/dev/null && osascript -e \
                      "display notification \"$url\" with title \"ClickFix-Lure gesichert\"" 2>/dev/null || true
                    if [[ -n "$RULE" ]] && command -v yara >/dev/null; then
                        yara -r "$RULE" "$dest" 2>/dev/null | sed 's/^/        yara: /' || true
                    fi
                else
                    echo "        kein Marker (gegated oder bereits bereinigt)"
                fi
            else
                echo "        Abruf fehlgeschlagen, siehe $dest.log"
            fi
        fi
    done <<< "$new"

    if [[ $PRIMED -eq 0 ]]; then
        echo "[$ts] Bestand vorgemerkt: $count Scans. Ab jetzt werden nur neue gemeldet."
        PRIMED=1
    elif [[ $count -eq 0 ]]; then
        echo "[$ts] nichts Neues"
    fi

    sleep "$INTERVAL"
done
