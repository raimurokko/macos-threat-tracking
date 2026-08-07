# Corrections

A record of claims we published here and later had to withdraw.

It exists because a repository that shows only its conclusions hides its error rate, and
the error rate is something a reader needs in order to decide how much of this to verify
independently. Every entry below was public before it was wrong in our own view — not a
draft, not a working note, but something someone could have acted on.

The case is the macOS ClickFix campaign tracked as DANTE, 2026-08. Five entries in four
days. The companion note in
[raimurokko/research](https://github.com/raimurokko/research/blob/main/notes/2026-08-clickfix-single-use-gate/README.md)
works through what they have in common; this file is the ledger.

---

## 1. "A chain that cannot be analysed twice"

**Published** 2026-08-05 · **withdrawn** 2026-08-06

**Claimed:** the stage-1 gate burns its token on first contact, so the payload is
unrecoverable once a victim or an analyst has spent it.

**Actually:** the token is single-use, the *lure* is not. A second visit issues a fresh
token and the chain runs again. The gate delays analysis; it does not prevent it.

**Found by:** revisiting a still-serving lure, two days later, for an unrelated reason.

**Cost:** two days of treating the sample as unobtainable, during which the delivery
infrastructure could have gone down and taken the sample with it.

---

## 2. The `user` / `BuildID` header pair, presented as our finding

**Published** 2026-08-06 · **corrected** 2026-08-06

**Claimed:** two non-standard request headers, emitted by the builder rather than the
hosting, are the most durable indicators in the chain.

**Actually:** the first half holds. The novelty did not — a SigmaHQ emerging-threats rule
published 2025-11-22 already matched `curl` POSTs carrying `user:` together with
`BuildID`, filed under Atomic macOS Stealer.

**Found by:** a duplicate search performed to prepare a rule contribution, not to check
the claim.

**Cost:** none externally. The correction landed before the indicators were relied on.

---

## 3. A correction that was itself wrong

**Published** 2026-08-06 · **reverted** 2026-08-07

**Claimed:** the 69,632-byte encrypted section is in `__DATA,__const`. This was entered as
a *correction* to an earlier, accurate statement.

**Actually:** `__DATA_CONST,__const`, in both architecture slices. `__DATA` holds 194
bytes in total. The 14-byte `__cstring` section that prompted the change is in `__TEXT`.

**Found by:** re-deriving the section layout from `otool -l` while working on the
decryption, which needed the real offsets.

**Cost:** anyone who had trusted the corrected figure would have looked in the wrong
segment. The original was right; a verification pass made it wrong.

---

## 4. "Not documented for AMOS"

**Published** 2026-08-07 · **withdrawn** 2026-08-07, same day

**Claimed:** the payload's two root LaunchDaemons and its replacement of Ledger, Trezor
and Exodus were not part of published AMOS behaviour, and that this argued *against* an
AMOS labelling.

**Actually:** both are documented AMOS activity since 2025-11, down to the identical
archive names `app.zip`, `apptwo.zip` and `appex.zip` under a `/zxc/` path on unrelated
hosts. Far from arguing against the labelling, they are among the strongest arguments for
it. The family assessment moved from *AMOS lineage, assessed* to **AMOS, confirmed**.

**Found by:** a duplicate search performed to prepare a rule contribution. The same
mechanism as entry 2, seventeen hours after entry 2 was written up.

**Cost:** a few hours of a wrong family assessment being public. Had it not been corrected,
a recipient acting on it would have under-weighted a confirmed family in favour of an open
question.

---

## 5. "A Cloudflare-fronted domain gives an investigator nothing"

**Published** 2026-08-06 · **corrected** 2026-08-07

**Claimed:** only an unproxied origin IP identifies a provider who can be served a
subscriber-data request; a proxied domain leaves nothing to act on.

**Actually:** proxying does not remove the lead, it relocates it. Cloudflare holds the
origin IP and the account that configured the service, and has a documented
law-enforcement request process. Ranked by what is realistically obtainable, the proxied
host was the *better* target in this case, not the worse one.

**Found by:** a question from a reader who noticed that a draft advisory named one hosting
provider and not the other.

**Cost:** the highest of the five, and the only one that reached a document intended for
recipients outside this project. A draft notification to an affected party omitted the
most productive provider — not from a fresh judgement, but because this repository had
already appeared to settle the question. A wrong conclusion in a reference document is
more expensive than a wrong conclusion in a working note.

---

## What these have in common

**None of them was caught by rereading our own text.** Four were caught by a mechanical
step taken for an unrelated purpose — a duplicate search before contributing rules, a
disassembly needed for something else, an investigation into why a rule would not deploy.
The fifth was caught by an outside question.

Being aware of the tendency did not help. Entry 4 was written hours after entry 2 was
published, in a note whose subject was entry 2.

Three of the five were **novelty claims**: something was called new without a search
having been performed. One was an **impossibility claim** — that a key could not be
recovered statically — which the same day turned out to be a 32-bit value with a
verification oracle. Impossibility and novelty are the two claims that produce no
contradiction while you hold them. Nothing pushes back, the work stops, and the stopping
feels like a result.

The errors did not come from one place. They came from both the human and the LLM-assisted
parts of this work, and in one case from a correction pass that was itself unverified.
Attributing them to one or the other would be a fifth kind of unchecked claim.

## What changed

Not "more care". Care was not the missing ingredient — the searches that eventually found
these took minutes each, and doing them more slowly would have changed nothing. Doing them
**earlier in the sequence** would have changed everything.

1. **Prior-art search before the first draft, not before submission.** Every search that
   caught something here was performed for a downstream reason. Work that is never
   submitted anywhere never gets that check, which means the error simply stands.
2. **No novelty claim ships without a named search.** "New" is a claim about the
   literature, not about our notes, and it carries the same evidentiary burden as any
   other claim in this repository.
3. **Before asserting that something is impossible, count the search space.** In entry 4's
   neighbour the number was already written down: 32 bits, with a Poly1305 tag as an
   oracle. "We could not find it" and "it cannot be found" are different claims, and only
   the first one is free.
4. **A verification pass is not automatically right.** Entry 3 was a correction that
   introduced an error. Re-derive from the artefact, not from the previous reading of it.

This is where taking more time actually applies: the time is for those four checks, before
publishing rather than after. That is a step whose execution can be seen in a diff. A
resolution to be more careful is not.

## Handling

Corrections stay visible. Entries are not edited away, and the original wording is quoted
in each case, because a claim that was public is part of the record whether or not it
survived. Where a superseded passage remains in place — as in `payload_analysis.md` — it
carries a marker rather than being deleted: the reasoning was sound on the evidence then
available, and what changed was the evidence.

*Deutsche Fassung: [CORRECTIONS.de.md](CORRECTIONS.de.md)*
