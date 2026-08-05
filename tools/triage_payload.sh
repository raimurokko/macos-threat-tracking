#!/usr/bin/env bash
#
# Statische Triage eines abgegriffenen Payloads.
# Liest die Datei nur. Kein exec, kein chmod +x, keine Pipe in eine Shell.
#
set -euo pipefail

[[ $# -eq 1 ]] || { echo "Aufruf: $0 <datei>" >&2; exit 2; }
F="$1"
[[ -f "$F" ]] || { echo "Nicht gefunden: $F" >&2; exit 2; }

# chmod 000 aus dem Capture-Schritt fuer die Lesezugriffe kurz aufheben
ORIG_MODE="$(stat -f '%Lp' "$F" 2>/dev/null || stat -c '%a' "$F")"
chmod 400 "$F"
restore() { chmod "$ORIG_MODE" "$F" 2>/dev/null || true; }
trap restore EXIT

hr() { printf '%.0s=' {1..72}; echo; }

hr; echo "DATEI"; hr
ls -l "$F"
command -v file >/dev/null && file "$F" || echo "(file nicht verfuegbar)"

hr; echo "HASHES"; hr
if command -v sha256sum >/dev/null; then
    sha256sum "$F"; md5sum "$F"
else
    shasum -a 256 "$F"; md5 "$F"
fi

hr; echo "ERSTE 64 BYTES (hex)"; hr
head -c 64 "$F" | od -A x -t x1z | head -5

hr; echo "KOPF ALS TEXT"; hr
head -c 2000 "$F" | LC_ALL=C tr -d '\000' | head -40

hr; echo "AUFFAELLIGE STRINGS"; hr
PATTERNS='https\?://|curl |wget |osascript|security find-|dscl |chmod \+x|launchctl|LaunchAgents|LaunchDaemons|base64|openssl|Keychain|login\.keychain|/Library/|~/\.ssh|Exodus|Electrum|MetaMask|Coinomi|Ledger|Cookies|Login Data|/tmp/|/var/folders'
if command -v strings >/dev/null; then
    strings -n 6 "$F" | grep -E -i "$PATTERNS" | sort -u | head -60
else
    LC_ALL=C tr -c '[:print:]\n' '\n' < "$F" | grep -E -i "$PATTERNS" | sort -u | head -60
fi

hr; echo "URLS UND HOSTS"; hr
if command -v strings >/dev/null; then
    strings -n 6 "$F" | grep -Eo 'https?://[^"'"'"' )]+' | sort -u
else
    LC_ALL=C tr -c '[:print:]\n' '\n' < "$F" | grep -Eo 'https?://[^"'"'"' )]+' | sort -u
fi

# Mach-O? Dann Load Commands, aber nichts ausfuehren.
if command -v file >/dev/null && file "$F" | grep -qi 'mach-o'; then
    hr; echo "MACH-O"; hr
    command -v otool >/dev/null && otool -hlv "$F" | head -60 || true
    command -v codesign >/dev/null && codesign -dvvv "$F" 2>&1 | head -20 || true
fi

hr; echo "HINWEISE"; hr
cat <<'EOF'
Shell-Skript?  Dann liest du es einfach durch. Dort steht, was nachgeladen wird
               und wonach gegriffen wird -> das ergibt die Familienzuordnung.
Mach-O?        Gehoert zu MalwareBazaar. Danach bei ThreatFox das "unknown"
               durch das korrekte Malpedia-Label ersetzen.
Leer/HTML?     Gate hat abgewiesen oder Infrastruktur ist abgeschaltet.

Die Datei bleibt nicht ausfuehrbar. Nicht doppelklicken, kein Quick Look,
nicht per AirDrop oder Shared Folder auf den Host kopieren.
EOF
