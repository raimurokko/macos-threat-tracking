# Cluster expansion: 29 domains sharing this campaign's stage-2 host

**Compiled:** 2026-08-04, ~18:10 UTC · Novum Analytica GmbH, Berlin · TLP:CLEAR
**Relates to:** [`writeup.md`](writeup.md) — same operator, wider infrastructure

> Hosts are defanged for reading. Live forms are in [`cluster_domains.csv`](cluster_domains.csv).

## Method — and what it did to the "no contact" claim

Two passes, deliberately kept apart:

1. **Passive.** urlscan.io search API (`task.tags:clickfix`), anonymous, plus the
   screenshot endpoint, which needs no key. No attacker host touched.
2. **Active.** Eight GET requests via `tools/grab_lure.sh` against candidate lures,
   download-only, nothing rendered or executed.

`writeup.md` states that no attacker host was contacted. That remains true **for the
original 14:42 UTC analysis** and must stay scoped to it — the second pass above
contacted attacker infrastructure from a Berlin residential address. Anyone reusing
these notes should not carry the original claim over to this document.

## What links the batch to this campaign

A single ThreatFox submission at 16:56 UTC (via `@clickfixhunter`) covers 29 apex
domains. One of them is `ferncurrent14[.]com` — the stage-2 loader host already
documented in `writeup.md`. The batch is therefore not a generic ClickFix sweep but
overlaps this operator's infrastructure directly.

A second, structural link: `enter-pverif-code[.]info` (our gating host, registered
0 days ago) appears alongside `makeverizyjar[.]info` — also 0 days old, and answering
with a response of **identical length (294 B)**. Same role, same age, same response
size. Treat it as a sibling gating host — since corroborated by shared hosting
infrastructure, see the 2026-08-06 addendum below.

## Infrastructure split

The batch separates cleanly by domain age, and the split matches the roles:

**Young — attacker-registered (≤ 6 days), the moving parts**

| Domain | Age | Resp. | Assessed role |
|---|---|---|---|
| `enter-pverif-code[.]info` | 0 d | 294 B | gating (confirmed, this campaign) |
| `makeverizyjar[.]info` | 0 d | 294 B | gating (suspected sibling) |
| `ferncurrent14[.]com` | 1 d | 27 KB | stage-2 loader (confirmed, this campaign) |
| `glentraverse[.]com` | 1 d | 1.1 KB | lure host, path `/kos` |
| `enter-press-cdn[.]com` | 2 d | 133 KB | lure host, CDN-styled name |
| `borrovnou4421[.]icu` | 2 d | 1.1 KB | throwaway, patterned name |
| `general-sample[.]space` | 4 d | 33 KB | lure host |
| `regenerate5141[.]icu` | 6 d | 555 B | throwaway, patterned name |

**Older — compromised legitimate sites, the delivery surface**

`betensured-tips[.]com`, `coogeechamber[.]com[.]au`, `danielklijn[.]com`,
`determinedresults[.]com`, `essentiel-leman[.]com`, `globalprotection[.]services`,
`indusrocktool[.]co[.]in`, `lexingtoncancerfoundation[.]org`, `liobet[.]org`,
`mca[.]ca`, `minisa[.]be`, `mon-banana-06[.]cfd`, `muhammedmuheisen[.]com`,
`paloaltopnetwork[.]site`, `soyseaw[.]com`, `synergytms[.]com`, `thetayf[.]com`,
`thu-ipad-03[.]cfd`, `ubiqueags[.]org`, `v-k[.]com[.]ua`, `wijnbarvicini[.]nl`

Mostly WordPress, ages 419–3552 days. **Do not block these wholesale** — same reasoning
as for the school site in `writeup.md`: they are victims, not attacker property.

Two are typosquats rather than compromised sites and can be treated as attacker-owned:
`paloaltopnetwork[.]site` (for `paloaltonetworks.com`) and `globalprotection[.]services`.

## Windows variant — now evidenced

`writeup.md` calls a Windows variant "likely but unobserved". The batch contains
`v-k[.]com[.]ua/vcapcha[.]ps1` — a PowerShell file named after a fake captcha. That is
the Windows arm of the same technique, delivered from the same cluster. It does not
change the macOS detection logic, but it settles the open question.

Note this also bounds `clickfix_fake_captcha_page.yar`: the rule requires all of
`Terminal`, `Command`, `Space`, `Enter` and will not fire on the Windows variant
(`Win+R` / Run dialog). That is intended, not a gap — but a Windows sibling rule is
the obvious follow-up.

## Live capture: negative result

Eight targets retrieved shortly after 18:08 UTC — roughly 70 minutes after the
16:56:50 UTC ThreatFox submission. (The exact retrieval timestamps were not
preserved; the working copy was created at 18:08 UTC and the fetches followed
immediately, so treat the gap as ~70 minutes, not a precise figure.)

| Target | Result |
|---|---|
| `download.globalprotection[.]services` | 404 behind Cloudflare |
| `globalprotection[.]services` | 521, origin down |
| `download.paloaltopnetwork[.]site` | 522, origin timeout |
| `glentraverse[.]com/kos` | 404 (nginx); urlscan saw 1168 B 1 h earlier |
| `minisa[.]be`, `soyseaw[.]com`, `danielklijn[.]com`, `muhammedmuheisen[.]com` | clean original pages, no injection |

`yara` over all captures with `clickfix_fake_captcha_page.yar`: **no match**. A referer
bypass (`google.com`, `t.co`) with a macOS Safari UA changed nothing.

The decisive observation is passive: urlscan's own screenshots show the **same** clean
pages, and 403 for the attacker-owned hosts. The scanner was gated out exactly as we
were — so a urlscan API key and the archived DOM would not have helped for this batch
either. The gating is stronger than user-agent or referer; one-shot-per-IP, geo
filtering, or a required redirect chain from malvertising all fit the evidence.

**Operational takeaway:** for this campaign the lure is retrievable only inside a window
well under an hour, if at all from a research address. Chasing third-party lures is
the weaker path to a reference sample. The injected block from a site we already have
an incident relationship with is authentic, attacker-controlled, and excisable from its
page context — that is where `clickfix_fake_captcha_page.yar` should get its
`yarahub_reference_md5`.

## Addendum 2026-08-06: the gates are not behind the proxy

Re-checked two days later. All three attacker domains still resolve, but only one of
them is actually proxied:

| Domain | A record | AS | Note |
|---|---|---|---|
| `enter-pverif-code[.]info` | 178.16.52.101 | **AS202412** | Cloudflare NS, DNS-only record — origin exposed |
| `makeverizyjar[.]info` | 158.94.208.87 | **AS202412** | same |
| `ferncurrent14[.]com` | 188.114.96.3 / .97.3 | AS13335 | Cloudflare, proxied |

AS202412 is `OMEGATECH-AS — Omegatech LTD`, an autonomous system registered
**2026-01-12**. Both answers were confirmed identical against two independent resolvers
(1.1.1.1 and 8.8.8.8).

Two consequences:

1. **`makeverizyjar[.]info` is no longer just a structural guess.** The earlier
   assessment rested on matching age and an identical response length. It now shares an
   autonomous system with the confirmed stage-1 gate, which is a materially stronger
   link. Still short of proof — an AS can host unrelated customers — but it moves the
   confidence from "suspected sibling" to "same hosting infrastructure".
2. **There is something for legal process to act on.** An unproxied origin IP names the
   hosting provider directly. For the two gates, that door is open without anyone having
   to be asked.

   **Corrected 2026-08-07.** This point originally began "A Cloudflare-fronted domain
   gives an investigator nothing". That is wrong. Proxying does not remove the lead, it
   relocates it: Cloudflare holds the origin IP for `ferncurrent14[.]com` together with
   the account that configured it, and is a US company with a documented law-enforcement
   request process. Ranked by realistic yield the proxied host is the *better* target
   here — Cloudflare answers, whereas AS202412 is seven months old with no visible
   legitimate business and may not. "Not visible to me" is not "not obtainable".

**What this does *not* say.** Registry country fields are not locations. The cleanest way
to see that is to collect them: for these same two origin IPs, four sources give four
different countries.

| Source | Country |
|---|---|
| Registration of AS202412 | SC — Seychelles |
| RIPE maintainer of the netblocks (`lir-tr-mgn-1-MNT`) | TR — Turkey |
| `country:` field in the RIPE `inetnum` object | DE — Germany |
| AlienVault OTX annotation | GB — United Kingdom |

None of these is false. The AS is registered in the Seychelles, the address space is
administered through a Turkish LIR, the registrant states a German address, and OTX reads
a stale database from when `158.94.0.0/16` was UK academic space — which also means the
OTX value should not be relied on at all.

Verified against live BGP data (RIPEstat) and Team Cymru on 2026-08-06: both prefixes are
announced by **AS202412**, and the RIPE `inetnum` objects for both carry `netname:
OMEGATECH`, org `ORG-OL329-RIPE`. That is the stable part, and it is the part without a
country attached. Infrastructure is rented; the useful finding is the *provider*, not the
flag — see also the scope note in `writeup.md`.

Service state: the gate still resolves but no longer answers on its root path (connection
fails). DNS alive, service gone — consistent with the operator moving on rather than with
a takedown.

## Caveats

- Inclusion in a ThreatFox batch means *submitted as suspected*, not *confirmed lure*.
  Nothing here was verified to have served an overlay except via the submitter's claim.
- Domain ages come from urlscan's `apexDomainAgeDays` and are indicative, not registry
  truth. `glentraverse[.]com` reporting 1 day alongside an established-looking site is
  the kind of value worth re-checking against WHOIS before it is relied on.
- Response sizes are from a single retrieval each and reflect the gated response, not
  what a victim would receive.
