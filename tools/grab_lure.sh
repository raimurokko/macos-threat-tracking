#!/usr/bin/env bash
#
# Sichert eine ClickFix-Lure-Seite und alle von ihr eingebundenen Skripte.
#
# Laedt nur herunter. Fuehrt nichts aus, rendert nichts, oeffnet keinen Browser.
# Anders als capture_stage2.sh wird hier kein Token verbraucht - die Lure-Seite
# ist statisches HTML, der Abruf ist folgenlos wiederholbar.
#
# Ergebnis: page.html plus je eine Datei pro eingebundenem Script. Fuer eine
# YARAhub-Einreichung nimmst du NICHT page.html, sondern die angreifer-
# kontrollierte Script-Datei - siehe Hinweis am Ende.
#
set -euo pipefail

URL="${1:-}"
[[ -n "$URL" ]] || { echo "Aufruf: $0 <url> [outdir]" >&2; exit 2; }
OUT="${2:-lure_$(date -u +%Y%m%dT%H%M%SZ)}"
UA="${UA:-Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15}"

mkdir -p "$OUT"
CURL=(curl --silent --show-error --max-time 30 --location --user-agent "$UA")
# Referer laesst sich fuer gegatete Lures ueber REFERER=... setzen; viele
# Kampagnen liefern das Overlay nur bei passendem Verweis aus.
[[ -n "${REFERER:-}" ]] && CURL+=(--referer "$REFERER")

echo "[1/3] Seite wird geladen ..."
"${CURL[@]}" --dump-header "$OUT/page_headers.txt" --output "$OUT/page.html" "$URL"
[[ -s "$OUT/page.html" ]] || { echo "Leere Antwort."; exit 3; }
echo "      $OUT/page.html ($(wc -c < "$OUT/page.html" | tr -d ' ') Bytes)"

echo "[2/3] Eingebundene Skripte ..."
BASE="$(printf '%s' "$URL" | sed -E 's#(https?://[^/]+).*#\1#')"

# grep liefert Exit 1, wenn die Seite das Overlay rein inline traegt - der
# haeufigste ClickFix-Fall. Mit pipefail wuerde set -e hier abbrechen, noch
# bevor Schritt 3 laeuft. Deshalb Trefferliste separat und fehlertolerant.
srclist="$OUT/.script_srcs"
grep -oE '<script[^>]+src=["'"'"'][^"'"'"']+' "$OUT/page.html" \
  | sed -E 's/.*src=["'"'"']//' | sort -u > "$srclist" || true

if [[ ! -s "$srclist" ]]; then
    echo "      keine externen <script src=...> - Overlay vermutlich inline"
else
    while read -r src; do
        [[ -n "$src" ]] || continue
        case "$src" in
            http*)  full="$src" ;;
            //*)    full="https:$src" ;;
            /*)     full="${BASE}${src}" ;;
            *)      full="${URL%/*}/$src" ;;
        esac
        name="script_$(printf '%s' "$full" | tr -c 'A-Za-z0-9._-' '_' | tail -c 60).js"
        if "${CURL[@]}" --output "$OUT/$name" "$full"; then
            printf '      %-58s %s\n' "$name" "$full"
            printf '%s  %s\n' "$name" "$full" >> "$OUT/script_sources.txt"
        fi
    done < "$srclist"
fi
rm -f "$srclist"

echo "[3/3] Auffaellige Dateien ..."
hits=0
for f in "$OUT"/page.html "$OUT"/script_*.js; do
    [[ -f "$f" ]] || continue
    if grep -qiE 'clipboard\.writeText|execCommand.*copy|ClipboardItem' "$f"; then
        if command -v md5sum >/dev/null; then M=$(md5sum "$f" | cut -d' ' -f1)
        else M=$(md5 -q "$f"); fi
        echo "      TREFFER  $(basename "$f")  md5=$M"
        hits=$((hits+1))
    fi
done
[[ $hits -gt 0 ]] || echo "      kein Clipboard-Marker - Lure evtl. gegated (UA/Referer/Geo) oder schon bereinigt"

cat <<'EOF'

Weiter:
  python3 prepare_yarahub.py --sample <treffer-datei> \
        --rule detection/yara/clickfix_fake_captcha_page.yar

  Das Skript prueft selbst, ob die Regel auf die Datei matcht, und lehnt ab,
  wenn nicht.

WICHTIG - was du hochlaedst:
  Bevorzugt die angreiferkontrollierte Script-Datei, nicht page.html.
  page.html enthaelt Titel, Pfade und Inhalte der kompromittierten Website.
  Auf YARAify ist das oeffentlich einsehbar - damit waere die Anonymisierung
  der Betreiberseite hinfaellig.

  Steckt das Overlay inline im HTML, schneide nur den injizierten Block in eine
  eigene Datei und nimm diese als Referenz.

  Ausnahme: Liegt die Lure auf einer rein angreifereigenen Domain (Typosquat
  wie download.paloaltopnetwork.site), gibt es keine Betreiberseite zu schuetzen
  - dann ist page.html als Referenz unbedenklich.
EOF
