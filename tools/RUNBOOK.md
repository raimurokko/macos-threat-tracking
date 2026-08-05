# Stage-2 Capture Runbook — ClickFix (macOS), Kampagne 2026-08-04

**Ziel:** Die zweite Stufe abgreifen und auf Platte legen, **ohne dass jemals eine Shell
sie zu sehen bekommt.** Der gesamte Aufbau ist darauf ausgelegt, dass ein Fehlgriff
nichts ausführt.

**Grundregel, die alles andere trägt:** Nirgendwo in diesem Runbook steht eine Pipe in
`sh`, `zsh` oder `bash`. Wenn du beim Nacharbeiten irgendwo eine tippst, hast du den Zweck
des Aufbaus zerstört.

---

## 0. Bedrohungsmodell des Aufbaus

Was schiefgehen kann, und was dagegen steht:

| Risiko | Gegenmaßnahme |
|---|---|
| Payload wird versehentlich ausgeführt | Abruf ausschließlich mit `curl -o`, nie mit Pipe |
| Payload greift beim Betrachten | Triage rein statisch, kein Öffnen im Finder, kein Quick Look |
| VM bricht aus / kontaktiert LAN | Eigenes isoliertes Netz, kein Bridged Mode, keine Shared Folders |
| Analyse-Host wird infiziert | Payload verlässt die VM nur als Hash + Base64-Text, nie als Datei |
| Token wird verschwendet | Reihenfolge strikt einhalten (Abschnitt 3) |
| Betreiber erkennt Analyse und schaltet ab | Nur ein Versuch, keine Wiederholungen aus derselben Quelle |

---

## 1. Virtualisierung

**Apple Silicon:** UTM (Virtualization.framework) oder Tart. macOS-Gast ab Ventura.
**Intel-Mac oder Linux-Host:** VMware Fusion/Workstation oder VirtualBox.

Für den reinen Abruf reicht auch eine **Linux-VM** — `curl` ist `curl`. macOS als Gast
brauchst du nur, wenn du zusätzlich das Verhalten der Lure-Seite gegenüber einem echten
Safari beobachten willst (Abschnitt 3a). Wenn dir das Sample genügt: Linux nehmen, ist
schneller aufgesetzt und snapshot-freundlicher.

**Pflicht vor allem anderen:**

- Snapshot anlegen, *bevor* die VM je im Netz war. Name z. B. `clean-baseline`.
- Shared Folders **aus**. Clipboard-Sharing **aus**. Drag & Drop **aus**.
  Das sind die drei Wege, auf denen Samples versehentlich auf den Host wandern.
- Netzwerk auf **Host-only + kontrollierter Gateway**, nicht Bridged.
- Keine Anmeldung an irgendeinem Konto in der VM. Kein iCloud, kein Browser-Sync.

---

## 2. Netzwerk und mitmproxy

Der Proxy sitzt auf dem Host (oder einer zweiten Linux-VM) und ist das einzige Tor der
Analyse-VM ins Internet.

```sh
pip install mitmproxy
mkdir -p ~/lab/flows ~/lab/artifacts
mitmdump -s mitm_addon.py --set confdir=~/.mitmproxy \
         -w ~/lab/flows/clickfix-$(date +%Y%m%d-%H%M).flow \
         --listen-port 8080
```

In der VM den Proxy auf `HOST_IP:8080` setzen und das mitmproxy-CA-Zertifikat
installieren (`http://mitm.it` im Gast-Browser). Nur nötig, wenn du HTTPS aufbrechen
willst — für den reinen `curl`-Abruf reicht `--proxy` ohne CA-Installation, siehe
Skript.

Parallel ein pcap mitschreiben, falls du später Details brauchst, die der Proxy nicht
sieht:

```sh
sudo tcpdump -i any -w ~/lab/flows/clickfix-$(date +%Y%m%d-%H%M).pcap \
     'host ferncurrent14.com or host enter-pverif-code.info'
```

---

## 3. Ablauf

Die Reihenfolge ist nicht verhandelbar. Das Gate gibt pro Token **einmal** `ok` zurück;
ein Fehlversuch verbrennt es.

### 3a. Frisches Token holen

In der VM die Lure-Seite im Browser öffnen. **Nichts einfügen, nichts ins Terminal.**
Die Seite schreibt das Kommando beim Laden in die Zwischenablage — du liest es dort aus:

```sh
# macOS-Gast
pbpaste > ~/lab/artifacts/clipboard_$(date +%s).txt

# Linux-Gast
xclip -selection clipboard -o > ~/lab/artifacts/clipboard_$(date +%s).txt
```

Alternativ liest der mitmproxy-Addon den Blob direkt aus dem Seiten-JavaScript mit
(Abschnitt 4) — das ist der sauberere Weg, weil er ohne Zwischenablage auskommt.

Aus dem Clipboard-Inhalt das Token extrahieren:

```sh
python3 decode_payload.py ~/lab/artifacts/clipboard_TIMESTAMP.txt
```

Das Skript dekodiert beide Base64-Schichten und gibt Gate-URL, Stage-2-URL und Token
aus — **ohne irgendetwas auszuführen.**

### 3b. Gate abfragen

```sh
./capture_stage2.sh --gate-url 'GATE_URL_AUS_3a' --stage2-url 'STAGE2_URL_AUS_3a'
```

Das Skript fragt zuerst das Gate ab. Kommt nicht exakt `ok` zurück, bricht es ab und
lädt Stage 2 gar nicht erst an — dann war das Token schon verbraucht oder du bist
gefiltert worden.

### 3c. Stage 2 sichern

Erledigt dasselbe Skript im zweiten Schritt: Abruf mit `-o` in eine Datei, danach
sofort `chmod 000`, Hashes, Header-Mitschrift. Die Datei ist zu keinem Zeitpunkt
ausführbar.

---

## 4. Was du außerdem mitnehmen solltest

Wenn du schon dran bist, lohnt sich mehr als nur das Sample:

- **Die Lure-Seite selbst** — das injizierte `<script>`, seine Position im DOM, ob es
  inline oder extern nachgeladen wird. Das beantwortet der Schule die Frage, *wie* sie
  kompromittiert wurde. Der mitmproxy-Addon speichert alle Antworten mit.
- **Geräteabhängige Auslieferung** — dieselbe Seite mit Windows-UA und mit iOS-UA
  abrufen. Wenn eine PowerShell-Variante existiert, verdoppelt das den Wert deiner
  Meldung.
- **Header des Gates** — Set-Cookie, Server-Banner, Timing. Manche dieser Panels
  verraten die eingesetzte Software.

---

## 5. Nach dem Abruf

```sh
./triage_payload.sh ~/lab/artifacts/stage2_TIMESTAMP.bin
```

Rein statisch: Dateityp, Hashes, Strings, bei Mach-O die Load Commands. **Nicht
ausführen, nicht im Finder doppelklicken, nicht mit Quick Look ansehen.**

Ist es ein Shell-Skript (wahrscheinlich), liest du es einfach — dann steht dort, was es
nachlädt und wonach es greift, und du hast deine Familienzuordnung.

Ist es ein Mach-O, gehört es zu MalwareBazaar. Danach kannst du bei ThreatFox das
`unknown` durch das richtige Malpedia-Label ersetzen.

**Den Payload verlässt die VM nur als Hash und als Base64-Text**, nie als Datei über
Shared Folder oder AirDrop.

---

## 6. Aufräumen

VM auf `clean-baseline` zurücksetzen. Flows, pcap und Artefakte liegen auf dem Host und
bleiben. Wenn du das Sample behalten willst: passwortgeschütztes Archiv mit dem in der
Branche üblichen Passwort `infected`, damit kein Virenscanner es beim nächsten Backup
zerlegt.
