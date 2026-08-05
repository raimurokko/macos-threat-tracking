/*
    Aggregate include for all macOS ClickFix rules in this directory.

        yara index.yar /path/to/scan

    Rules are maintained one per file; this file exists only for convenience.
*/

include "clickfix_campaign_2026_08_04.yar"
include "clickfix_macos_generic_exec.yar"
include "clickfix_fake_captcha_page.yar"
