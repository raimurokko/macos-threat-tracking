/*
    Aggregate include for all macOS ClickFix rules in this directory.

        yara index.yar /path/to/scan

    Rules are maintained one per file - YARAhub accepts only one rule per submission.
    This file exists only for convenience.

    Note the mixed target types: the first three rules are for text artefacts (shell
    history, clipboard dumps, HTML), the two stage3 rules are for Mach-O. Running the
    index over a mixed tree is harmless but slower than picking the right rule.

    freshfix_payload_internals.yar adds a third target type. One of its three rules,
    FreshFix_Loader_AntiAnalysis_Memory, matches strings that exist only in a running
    process - it cannot fire on a file, by design, and its absence from a disk scan
    means nothing.
*/

include "clickfix_campaign_2026_08_04.yar"
include "clickfix_macos_generic_exec.yar"
include "clickfix_fake_captcha_page.yar"
include "clickfix_macos_stage3_loader.yar"
include "clickfix_macos_stage3_known_samples.yar"
include "freshfix_payload_internals.yar"
