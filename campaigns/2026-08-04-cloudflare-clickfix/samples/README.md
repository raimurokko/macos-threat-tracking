# Samples

Text artefacts only. **Nothing here is executable and nothing should be executed.**

| File | Stage | MD5 |
|---|---|---|
| `clipboard_payload_2169ff5e.txt` | 0 — what the lure wrote to the clipboard | `2169ff5e7be77fc3ff72758f9fa50658` |
| `stage2_fetched_script.txt` | 2 — fetched from the loader host after the gate returned `ok` | see below |
| `stage2_inner_decoded.txt` | 2 — the gzip+base64 blob from the above, decoded | see below |

Run `md5 *` in this directory for current values; they are not repeated here so that the
file cannot drift out of sync with itself.

## What is not here

**The stage-3 Mach-O.** Hashes are in `../iocs.csv` and the binary has been submitted to
MalwareBazaar, which is the right place for it. A git repository is not: the file would
be permanent, unversionable in any meaningful sense, and would make this repository
awkward to clone in environments with endpoint protection.

**The hand-deobfuscated stage 2.** The octal-escaped strings in
`stage2_inner_decoded.txt` were resolved by hand during analysis. That reading is
reproduced in `../payload_analysis.md`, where it belongs — as an interpretation, clearly
attributed. The transcript itself is not an artefact and is not kept: it contained a
transcription error, which is exactly the failure mode that keeps derived files out of a
sample directory.

## Handling

These are text files. They are safe to open in an editor, `cat`, `grep` and hash. They
are not safe to paste into a shell, which is the entire point of the technique they
belong to.
