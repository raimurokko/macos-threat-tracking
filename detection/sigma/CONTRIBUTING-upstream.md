# Contributing these Sigma rules upstream to SigmaHQ

Our rules live here in our own naming. SigmaHQ has its own conventions, so upstreaming
means renaming and relocating — not rewriting the logic. This is the checklist.

Verified against the SigmaHQ repository on 2026-08-06.

---

## 1. The two rules go to different places

SigmaHQ separates general detection logic from campaign-specific indicators.

| Our file | Goes to | As |
|---|---|---|
| `clickfix_stage3_dropper.yml` | `rules/macos/process_creation/` | `proc_creation_macos_clickfix_dropper_dequarantine.yml` |
| `clickfix_dante_endpoints_proxy.yml` | `rules-emerging-threats/2026/Malware/ClickFix-DANTE/` | `proxy_clickfix_dante_c2.yml` |

The dropper rule is behavioural — `curl` → `xattr -c` → `chmod +x` under an interactive
shell parent — and belongs in the main rule set.

The proxy rule matches hardcoded domains. SigmaHQ does not take IOC lists into `rules/`;
that is exactly what `rules-emerging-threats/` exists for. Existing siblings there
(`RedTail-Cryptominer`, `EvilTokens`) show the one-directory-per-campaign pattern.

**Filename convention:** lowercase, underscores throughout, `.yml`. OS-dependent
categories use `<category>_<os>_<description>.yml`, hence the `proc_creation_macos_`
prefix. Any dash in a service name becomes an underscore.

## 2. What to change in the files

Keep the detection logic. Change the metadata:

- **`author`** — SigmaHQ credits people or organisations, so `Novum Analytica GmbH` is
  fine as-is. This is the field that carries the attribution upstream; it is the whole
  point of contributing.
- **`id`** — must stay a UUID and must be *new*, not reused from our copy. If our rule
  and the upstream rule share an ID, anyone running both gets a collision. Generate a
  fresh one for the upstream version and keep ours unchanged.
- **`status`** — `experimental` is right for a new contribution. Do not claim `test` or
  `stable`; those are earned after the rule has been exercised.
- **`references`** — must be present in both rules. Point at
  `payload_analysis.md` and the MalwareBazaar sample, not at the repository root.
- **`falsepositives`** — required, and reviewers read it. "Unknown" invites a change
  request. For the dropper rule, name the real one: legitimate installers that fetch a
  binary and mark it executable.
- **`level`** — ours are `high` and `critical`. Expect a reviewer to push the proxy rule
  down; campaign-specific rules age out and a `critical` that fires on a dead domain is
  noise.

## 3. Validate before opening the PR

SigmaHQ runs these in CI and will bounce the PR otherwise:

```sh
git clone https://github.com/SigmaHQ/sigma && cd sigma
pip install sigma-cli pyyaml
python tests/test_rules.py        # structure, conventions, common mistakes
python tests/test_logsource.py    # valid logsource categories and field names
sigma check rules/                # schema and validation
```

`test_logsource.py` is the one that usually fails first: it rejects field names that do
not exist for the declared logsource. Our `process_creation` rule uses `ParentImage`,
`Image` and `CommandLine`, which are valid for macOS — but verify against their taxonomy
rather than assuming, because the macOS field set is smaller than the Windows one.

## 4. Before writing anything, check it does not already exist

Their contribution guide asks for this explicitly, and it is the most common reason a PR
is closed. ClickFix is widely covered by now.

```sh
grep -ril "clickfix" rules/ rules-emerging-threats/
grep -ril "xattr" rules/macos/
```

If something close exists, the better contribution is a PR that *extends* it — add the
`xattr -c` step to an existing dropper rule — rather than a second rule that overlaps.
Reviewers prefer that, and it gets merged faster.

## 5. PR shape

- One branch per contribution, off `master`.
- Both rules can go in one PR since they belong to one campaign; say so in the
  description.
- Describe what the rule detects and what it does *not*. Link the analysis and the
  sample. Reviewers respond well to a rule that states its own limits — our dropper rule
  will not fire if the operator drops the `xattr` step, and saying so up front is better
  than having it found.

## 6. What upstreaming does not change

Our copies stay here and stay maintained. The upstream versions get different IDs and
will drift. If we update a rule, updating the upstream copy is a separate PR — there is
no sync.
