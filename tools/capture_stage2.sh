#!/usr/bin/env bash
#
# Holt Stage 2 einer ClickFix-Kette und legt sie auf Platte.
#
# Der Payload wird NIE ausgeführt: Abruf ausschliesslich mit `curl -o`, die
# Zieldatei bekommt sofort chmod 000 und traegt die Endung .bin.
# Es gibt in diesem Skript keine Pipe in eine Shell. Das ist Absicht.
#
# Nur in einer isolierten Wegwerf-VM ausfuehren.
#
set -euo pipefail

OUTDIR="${OUTDIR:-$HOME/lab/artifacts}"
PROXY="${PROXY:-}"                       # z.B. http://10.0.2.2:8080
UA="${UA:-Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15}"
GATE_URL=""; STAGE2_URL=""; FORCE=0

usage() {
    sed -n '2,12p' "$0" | sed 's/^# \?//'
    cat <<'EOF'

Optionen:
  --gate-url URL     Stage-1 Gate (Pflicht)
  --stage2-url URL   Stage-2 Loader (Pflicht)
  --proxy URL        HTTP(S)-Proxy, z.B. mitmproxy
  --ua STRING        User-Agent; sollte dem Browser entsprechen, der das Token bekam
  --force            Stage 2 auch laden, wenn das Gate nicht "ok" sagt
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gate-url)   GATE_URL="$2"; shift 2 ;;
        --stage2-url) STAGE2_URL="$2"; shift 2 ;;
        --proxy)      PROXY="$2"; shift 2 ;;
        --ua)         UA="$2"; shift 2 ;;
        --force)      FORCE=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "Unbekannte Option: $1" >&2; usage; exit 2 ;;
    esac
done

[[ -n "$GATE_URL" && -n "$STAGE2_URL" ]] || { usage; exit 2; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUTDIR"
STAGE2_FILE="$OUTDIR/stage2_${TS}.bin"
LOG="$OUTDIR/capture_${TS}.log"

CURL=(curl --silent --show-error --max-time 30 --user-agent "$UA")
[[ -n "$PROXY" ]] && CURL+=(--proxy "$PROXY" --insecure)   # -k nur fuer mitmproxy-CA

log() { printf '%s  %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$LOG"; }

log "=== Capture $TS ==="
log "Gate:   $GATE_URL"
log "Stage2: $STAGE2_URL"
log "Proxy:  ${PROXY:-<keiner>}"
log ""

# --- Sicherheitsabfrage -----------------------------------------------------
cat <<'WARN'
Dieses Skript kontaktiert aktive Angreiferinfrastruktur.

  - Nur in einer isolierten Wegwerf-VM ausfuehren, niemals auf einem Arbeitsgeraet.
  - Das Gate gibt pro Token genau einmal "ok" zurueck. Ein Fehlversuch verbrennt es.
  - Deine IP wird dem Betreiber sichtbar.

WARN
read -r -p "Weiter? [ja/NEIN] " ok
[[ "$ok" == "ja" ]] || { log "Abgebrochen."; exit 1; }

# --- Schritt 1: Gate --------------------------------------------------------
log "[1/3] Gate wird abgefragt ..."
GATE_HDR="$OUTDIR/gate_headers_${TS}.txt"
GATE_BODY="$("${CURL[@]}" --dump-header "$GATE_HDR" "$GATE_URL" || true)"

log "Gate-Antwort: '${GATE_BODY}'"
log "Header abgelegt: $GATE_HDR"

if [[ "$GATE_BODY" != "ok" ]]; then
    log ""
    log "Gate hat NICHT 'ok' geliefert."
    log "Moegliche Gruende: Token verbraucht, IP/Geo gefiltert, User-Agent unpassend,"
    log "Infrastruktur bereits abgeschaltet."
    if [[ "$FORCE" -ne 1 ]]; then
        log "Abbruch. Mit --force trotzdem laden."
        exit 3
    fi
    log "--force gesetzt, es wird trotzdem geladen."
fi

# --- Schritt 2: Stage 2 in eine Datei, nicht in eine Shell -----------------
log ""
log "[2/3] Stage 2 wird in Datei geschrieben (keine Ausfuehrung) ..."
S2_HDR="$OUTDIR/stage2_headers_${TS}.txt"

"${CURL[@]}" --dump-header "$S2_HDR" --output "$STAGE2_FILE" "$STAGE2_URL" || {
    log "Abruf fehlgeschlagen."; exit 4; }

if [[ ! -s "$STAGE2_FILE" ]]; then
    log "Leere Antwort. Stage 2 wurde nicht ausgeliefert."
    rm -f "$STAGE2_FILE"; exit 5
fi

chmod 000 "$STAGE2_FILE"
log "Gespeichert: $STAGE2_FILE ($(wc -c < "$STAGE2_FILE" | tr -d ' ') Bytes, chmod 000)"

# --- Schritt 3: Provenienz --------------------------------------------------
log ""
log "[3/3] Hashes ..."
if command -v sha256sum >/dev/null; then
    SHA256="$(sha256sum "$STAGE2_FILE" | cut -d' ' -f1)"
    MD5="$(md5sum "$STAGE2_FILE" | cut -d' ' -f1)"
else
    SHA256="$(shasum -a 256 "$STAGE2_FILE" | cut -d' ' -f1)"
    MD5="$(md5 -q "$STAGE2_FILE")"
fi
log "SHA256: $SHA256"
log "MD5:    $MD5"

cat > "$OUTDIR/provenance_${TS}.json" <<EOF
{
  "captured_utc": "$TS",
  "gate_url": "$GATE_URL",
  "gate_response": "$GATE_BODY",
  "stage2_url": "$STAGE2_URL",
  "user_agent": "$UA",
  "proxy": "${PROXY:-null}",
  "sha256": "$SHA256",
  "md5": "$MD5",
  "size_bytes": $(wc -c < "$STAGE2_FILE" | tr -d ' '),
  "executed": false,
  "note": "Fetched to disk with curl -o. Never piped to a shell. chmod 000."
}
EOF

log ""
log "Provenienz: $OUTDIR/provenance_${TS}.json"
log ""
log "Naechster Schritt:  ./triage_payload.sh '$STAGE2_FILE'"
log "NICHT ausfuehren, nicht im Finder oeffnen, kein Quick Look."
