# Richtigstellungen

Ein Verzeichnis der Behauptungen, die wir hier veröffentlicht und später zurückgenommen
haben.

Es existiert, weil ein Repository, das nur seine Ergebnisse zeigt, seine Fehlerquote
verbirgt — und die Fehlerquote ist das, was eine Leserin braucht, um zu entscheiden, wie
viel davon sie unabhängig nachprüfen sollte. Jeder Eintrag unten war öffentlich, bevor er
aus unserer eigenen Sicht falsch wurde. Kein Entwurf, keine Arbeitsnotiz, sondern etwas,
worauf jemand hätte handeln können.

Der Fall ist die macOS-ClickFix-Kampagne DANTE, August 2026. Fünf Einträge in vier Tagen.
Die begleitende Notiz in
[raimurokko/research](https://github.com/raimurokko/research/blob/main/notes/2026-08-clickfix-single-use-gate/clickfix-single-use-gate.md)
arbeitet heraus, was sie gemeinsam haben; diese Datei ist das Verzeichnis.

---

## 1. „Eine Kette, die sich kein zweites Mal analysieren lässt"

**Veröffentlicht** 05.08.2026 · **zurückgenommen** 06.08.2026

**Behauptet:** Das Gate der ersten Stufe verbraucht sein Token beim ersten Kontakt, das
Payload sei danach nicht mehr zu beschaffen.

**Tatsächlich:** Das Token ist einmalig, die *Lure* nicht. Ein zweiter Besuch erzeugt ein
frisches Token, und die Kette läuft erneut. Das Gate verzögert die Analyse, es verhindert
sie nicht.

**Gefunden durch:** einen erneuten Besuch einer noch ausliefernden Lure, zwei Tage später,
aus einem anderen Anlass.

**Kosten:** zwei Tage, in denen das Sample als unerreichbar galt — Tage, in denen die
Auslieferungsinfrastruktur hätte verschwinden und das Sample mitnehmen können.

---

## 2. Das Header-Paar `user` / `BuildID` als eigener Fund dargestellt

**Veröffentlicht** 06.08.2026 · **korrigiert** 06.08.2026

**Behauptet:** Zwei nicht standardisierte Kopfzeilen, die vom Builder und nicht vom Hosting
stammen, seien die beständigsten Indikatoren der Kette.

**Tatsächlich:** Die erste Hälfte stimmt. Die Neuheit nicht — eine SigmaHQ-Regel vom
22.11.2025 trifft bereits `curl`-POSTs, die `user:` zusammen mit `BuildID` senden,
eingeordnet unter Atomic macOS Stealer.

**Gefunden durch:** eine Dublettensuche, die zur Vorbereitung eines Regelbeitrags
stattfand, nicht zur Prüfung der Behauptung.

**Kosten:** nach außen keine. Die Korrektur kam, bevor sich jemand darauf stützte.

---

## 3. Eine Korrektur, die selbst falsch war

**Veröffentlicht** 06.08.2026 · **zurückgenommen** 07.08.2026

**Behauptet:** Der 69.632 Byte große verschlüsselte Abschnitt liege in `__DATA,__const`.
Das wurde ausdrücklich als *Korrektur* einer zutreffenden früheren Angabe eingetragen.

**Tatsächlich:** `__DATA_CONST,__const`, in beiden Architektur-Slices. `__DATA` fasst
insgesamt 194 Byte. Die 14-Byte-`__cstring`, die den Anlass gab, liegt in `__TEXT`.

**Gefunden durch:** das erneute Ableiten des Sektionslayouts aus `otool -l` bei der Arbeit
an der Entschlüsselung, die die echten Offsets brauchte.

**Kosten:** Wer der korrigierten Angabe vertraute, hätte im falschen Segment gesucht. Das
Original war richtig; ein Prüfdurchgang hat es falsch gemacht.

---

## 4. „Für AMOS nicht dokumentiert"

**Veröffentlicht** 07.08.2026 · **zurückgenommen** 07.08.2026, am selben Tag

**Behauptet:** Die zwei Root-LaunchDaemons des Payloads und der Austausch von Ledger,
Trezor und Exodus seien nicht Teil veröffentlichter AMOS-Beschreibungen, und das spreche
*gegen* eine AMOS-Zuordnung.

**Tatsächlich:** Beides ist seit November 2025 dokumentierte AMOS-Aktivität, bis hin zu den
identischen Archivnamen `app.zip`, `apptwo.zip` und `appex.zip` unter einem `/zxc/`-Pfad
auf fremden Hosts. Weit davon entfernt, gegen die Zuordnung zu sprechen, gehören sie zu
den stärksten Argumenten dafür. Die Einstufung ging von *AMOS lineage, assessed* auf
**AMOS, bestätigt**.

**Gefunden durch:** eine Dublettensuche zur Vorbereitung eines Regelbeitrags. Derselbe
Mechanismus wie bei Eintrag 2, siebzehn Stunden nachdem Eintrag 2 aufgeschrieben worden
war.

**Kosten:** einige Stunden, in denen eine falsche Familieneinstufung öffentlich stand. Ohne
Korrektur hätte jemand, der darauf handelt, eine belegte Familie zugunsten einer offenen
Frage untergewichtet.

---

## 5. „Eine Cloudflare-fronted Domain gibt einem Ermittler nichts"

**Veröffentlicht** 06.08.2026 · **korrigiert** 07.08.2026

**Behauptet:** Nur eine ungeproxiede Origin-IP benenne einen Provider, dem sich eine
Bestandsdatenauskunft zustellen lässt; eine proxied Domain lasse nichts übrig, woran man
ansetzen kann.

**Tatsächlich:** Ein Proxy beseitigt den Ansatzpunkt nicht, er verlagert ihn. Cloudflare
hält die Origin-IP und das Konto, das den Dienst eingerichtet hat, und verfügt über ein
dokumentiertes Verfahren für Auskunftsersuchen. Nach dem, was realistisch zu erlangen ist,
war der proxied Host in diesem Fall der *bessere* Ansatzpunkt, nicht der schlechtere.

**Gefunden durch:** die Rückfrage einer Leserin, der auffiel, dass ein Entwurf für eine
Geschädigtenmitteilung einen Hosting-Provider nannte und den anderen nicht.

**Kosten:** die höchsten der fünf, und der einzige Fall, der ein Dokument für Empfänger
außerhalb dieses Projekts erreichte. In einem Entwurf für eine Mitteilung an eine
Geschädigte fehlte der ergiebigste Anbieter — nicht aus neuer Einschätzung, sondern weil
dieses Repository die Frage bereits beantwortet zu haben schien. Ein falscher Schluss in
einem Referenzdokument ist teurer als einer in einer Arbeitsnotiz.

---

## Was sie gemeinsam haben

**Keiner wurde durch das erneute Lesen der eigenen Texte gefunden.** Vier wurden durch
einen mechanischen Schritt gefunden, der aus anderem Anlass stattfand — eine
Dublettensuche vor einem Regelbeitrag, eine Disassemblierung für etwas anderes, die Frage,
warum eine Regel nicht ausgerollt wird. Der fünfte durch eine Rückfrage von außen.

Das Wissen um die Neigung half nicht. Eintrag 4 entstand Stunden nach der Veröffentlichung
von Eintrag 2, in einer Notiz, deren Gegenstand Eintrag 2 war.

Drei der fünf waren **Neuheitsbehauptungen**: Etwas wurde neu genannt, ohne dass gesucht
worden wäre. Einer war eine **Unmöglichkeitsbehauptung** — ein Schlüssel sei statisch nicht
zu ermitteln —, die sich am selben Tag als 32-Bit-Wert mit Prüforakel herausstellte.
Unmöglichkeit und Neuheit sind die beiden Behauptungen, die keinen Widerspruch erzeugen,
solange man sie hält. Nichts wehrt sich, die Arbeit endet, und das Enden fühlt sich an wie
ein Ergebnis.

Die Fehler stammen nicht aus einer Quelle. Sie stammen aus dem menschlichen wie aus dem
LLM-gestützten Teil dieser Arbeit, und in einem Fall aus einem Prüfdurchgang, der selbst
ungeprüft war. Sie dem einen oder dem anderen zuzuschreiben wäre eine fünfte Art
ungeprüfter Behauptung.

## Was sich ändert

Nicht „mehr Sorgfalt". Sorgfalt war nicht das Fehlende — die Suchen, die das hier
gefunden haben, dauerten jeweils Minuten, und sie langsamer zu machen hätte nichts
geändert. Sie **früher in der Reihenfolge** zu machen, hätte alles geändert.

1. **Vorarbeitssuche vor dem ersten Entwurf, nicht vor der Einreichung.** Jede Suche, die
   hier etwas gefunden hat, fand aus einem nachgelagerten Grund statt. Arbeit, die nirgends
   eingereicht wird, bekommt diese Prüfung nie — der Fehler bleibt dann einfach stehen.
2. **Keine Neuheitsbehauptung ohne benannte Suche.** „Neu" ist eine Aussage über die
   Literatur, nicht über unsere Notizen, und trägt dieselbe Beweislast wie jede andere
   Aussage in diesem Repository.
3. **Vor einer Unmöglichkeitsbehauptung den Suchraum abzählen.** Im Nachbarfall von
   Eintrag 4 stand die Zahl bereits da: 32 Bit, mit einem Poly1305-Tag als Orakel. „Wir
   haben es nicht gefunden" und „es ist nicht auffindbar" sind verschiedene Behauptungen,
   und nur die erste ist umsonst zu haben.
4. **Ein Prüfdurchgang hat nicht automatisch recht.** Eintrag 3 war eine Korrektur, die
   einen Fehler einführte. Neu ableiten aus dem Artefakt, nicht aus der vorherigen Lesart
   davon.

Hier greift das Sich-mehr-Zeit-Nehmen tatsächlich: Die Zeit ist für diese vier Prüfungen,
und zwar vor der Veröffentlichung statt danach. Das ist ein Schritt, dessen Ausführung man
in einem Diff sehen kann. Ein Vorsatz, sorgfältiger zu sein, ist es nicht.

## Umgang

Richtigstellungen bleiben sichtbar. Einträge werden nicht wegredigiert, und der
ursprüngliche Wortlaut wird jeweils zitiert, weil eine Behauptung, die öffentlich war, zum
Protokoll gehört — ob sie Bestand hatte oder nicht. Wo eine überholte Passage stehen
bleibt, wie in `payload_analysis.md`, trägt sie einen Vermerk statt gelöscht zu werden: Die
Begründung war auf dem damaligen Stand der Belege tragfähig, und geändert haben sich die
Belege.

*English version: [CORRECTIONS.md](CORRECTIONS.md)*
