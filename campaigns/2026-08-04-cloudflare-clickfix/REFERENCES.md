## References

Each claim in the attribution section maps to a specific source. Where a source supports
the assessment and where it constrains it are both recorded, because the constraints are
what keep the family field at `unknown`.

### Primary — chain and infrastructure

**[1] Microsoft Threat Intelligence — "From open lures to cloaked gates: How a macOS
ClickFix campaign learned to hide"** · 2026-08-05
https://www.microsoft.com/en-us/security/blog/2026/08/05/macos-clickfix-campaign-learned-hide/
Microsoft Security Research and Srinivasan Govindarajan.

Supports: the `/curl/<id>` staging URL as a campaign hallmark; the multi-stage script
chain terminating in an infostealer; the hunting guidance naming `curl` piped to `zsh`,
`base64 -d`, and `xattr -c` immediately preceding `chmod +x`.

Constrains: this is the source that keeps our attribution short of confirmed. Microsoft
states the same infrastructure cluster delivers **both** MacSync and AMOS, so chain shape
alone does not separate the two.

Differs: their front-end is mass-registered look-alike domains (`file<word><word>`) behind
a JavaScript fingerprinting gate. Ours was a compromised legitimate site behind a
server-side single-use token gate. Same back-end shape, different acquisition strategy —
see the front-end note in the analysis.

**[2] Microsoft Threat Intelligence — "ClickFix campaign uses fake macOS utilities lures
to deliver infostealers"** · 2026-05-06
https://www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/

Supports: the January–February 2026 campaign phase using an executable named `helper` or
`update`, a first-stage script decoding base64 then decompressing with gunzip, and
retrieval of a second-stage Mach-O into `/tmp/<name>`. This is the closest published
match to our stage-1 and stage-2 structure, including the filename.

### Primary — the terminal stage

**[3] Jamf Threat Labs — "ClickFix Malware Uses macOS Script Editor to Deliver Atomic
Stealer"** · 2026-04-08
https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/

Supports: the exact terminal sequence — Mach-O retrieved to `/tmp/helper`, extended
attributes stripped, execute bit set, run — and the `<path>/<campaign>/update` URL shape.
Their observed URL used a different campaign token in the same position where ours
carries `DANTE`. Jamf identifies the resulting binary as a recent AMOS variant.

Secondary coverage of the same Jamf research, useful where the original is paywalled or
unavailable:
- BleepingComputer, 2026-04-08 —
  https://www.bleepingcomputer.com/news/security/new-macos-stealer-campaign-uses-script-editor-in-clickfix-attack/
- GBHackers, 2026-04-09 — https://gbhackers.com/macos-script-editor-abused/

### Primary — binary characteristics

**[4] Palo Alto Networks Unit 42 — "ClickFix campaign delivers macOS infostealer via
DMG"** · 2026-06-20
https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-06-20-ClickFix-campaign-delivers-macOS-infostealer-via-DMG.txt

Supports: the assessment that the payload belongs to the AMOS lineage, specifically the
modern C++ "Odyssey" variant, described as a universal Mac executable combining Intel and
ARM64 architectures written in C++. Our sample matches that description at the file level:
universal Mach-O, both slices, `libc++` linked.

Note the delivery differs — Unit 42's case used a DMG, ours a `curl` fetch — so this
supports the *binary* assessment, not the chain.

### Supporting — family context and prevalence

**[5] Sophos — "Why AMOS matters: The macOS malware stealing data at scale"** · 2026-05-14
https://www.sophos.com/en-us/blog/why-amos-matters-the-macos-malware-stealing-data-at-scale

Supports: base rate. Sophos reports AMOS accounted for close to 40% of their macOS
protection updates in 2025, more than double any other macOS family. Also documents an
MDR incident beginning with a ClickFix-style ruse and resolving to an AMOS variant.

Constrains: the same post notes MacSync variants adopting the same social-engineering
approach in March 2025 — a second independent statement that the delivery method does not
identify the family.

**[6] Sophos — "Evil evolution: ClickFix and macOS infostealers"** · 2026-03-11
https://www.sophos.com/en-us/blog/evil-evolution-clickfix-and-macos-infostealers

**[7] LevelBlue / SpiderLabs — "macOS ClickFix Social Engineering Campaigns"** · 2026-06-04
https://www.levelblue.com/blogs/spiderlabs-blog/macos-clickfix-social-engineering-campaigns

Supports: the observation that ClickFix is not one operation but several competing groups
deploying AMOS, Cuckoo, MacSync and SHub, with locale-based filtering and dynamic C2
rotation as recurring traits. Useful framing for why family attribution from chain shape
is unreliable in this space generally.

**[8] SentinelOne — "From Amos to Poseidon: A SOC Team's Guide to Detecting macOS Atomic
Stealers"** · 2024-09-30
https://www.sentinelone.com/blog/from-amos-to-poseidon-a-soc-teams-guide-to-detecting-macos-atomic-stealers-2024/

Relevant as a caution rather than a support. It documents that the Atomic family has
splintered into competing offerings — Amos, Banshee, Cthulhu, Poseidon, RodrigoStealer —
sold by rival crimeware vendors, with samples in both Go and C++, and the authors state
they remain ambivalent about assigning a given sample to one family or another. That
ambivalence, from researchers with far more samples than we have, is the strongest
argument for leaving our family field open.

### Taxonomy and submission targets

**[9] Malpedia — `osx.amos` (AMOS, aka Atomic macOS Stealer)**
https://malpedia.caad.fkie.fraunhofer.de/details/osx.amos
The canonical family label, required by ThreatFox submissions.

**[10] ThreatFox — IOCs associated with `osx.amos`**
https://threatfox.abuse.ch/browse/malware/osx.amos/

**[11] Apple — Terminal paste protection, macOS 26.4**
https://support.apple.com/en-us/127377
Platform mitigation directly targeting the ClickFix delivery mechanism, referenced by [1].

---

### Summary of the evidential position

Four independent vendors describe the same terminal sequence resolving to AMOS. One of
them ([1]) states plainly that the same infrastructure also delivers MacSync, and a
second ([5]) independently reports MacSync using the identical social-engineering
approach. A third ([8]) reports that even well-resourced researchers do not reliably
separate members of the Atomic family from one another.

The chain-level match is strong. The family-level inference it would support is not, and
no amount of additional chain evidence would change that — only the decrypted payload
would. Hence: **AMOS lineage, assessed, medium-high confidence**, with the machine-readable
family field left at `unknown` pending an independent verdict on the submitted sample.
