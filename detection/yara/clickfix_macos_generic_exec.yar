/*
    Generic macOS ClickFix execution pattern.

    Catches the shape rather than the campaign: an eval over a base64-decoded blob,
    and/or a curl fetch piped straight into a shell.

    TUNE BEFORE ALERTING. Developer bootstrappers (Homebrew, rustup, nvm) and internal
    provisioning scripts legitimately do both of these. The high-fidelity signal is this
    pattern PLUS an interactive Terminal parent PLUS a young domain -- YARA alone only
    gives you the first part. Best used for hunting and triage, not for paging someone.
*/

rule ClickFix_macOS_Generic_ClipboardExec : clickfix macos behaviour
{
    meta:
        author       = "Novum Analytica GmbH"
        date         = "2026-08-04"
        description  = "Generic ClickFix execution pattern on macOS: eval of decoded blob, or curl piped to a shell"
        reference    = "https://github.com/raimurokko/macos-threat-tracking"
        severity     = "high"
        mitre_attack = "T1204.004, T1059.004, T1027.013"
        tlp          = "TLP:CLEAR"
        license      = "CC0-1.0"
        note         = "Expect false positives from developer tooling. Tune first."

    strings:
        $eval1  = "eval \"$(printf"            ascii
        $eval2  = "eval $(printf"              ascii
        $eval3  = "eval \"$(echo"              ascii

        $b64a   = "base64 -d"                  ascii
        $b64b   = "base64 --decode"            ascii
        // openssl instead of base64 evades signatures keyed on the obvious form
        $b64c   = "openssl base64 -d -A"       ascii

        $pipe1  = "| zsh"                      ascii
        $pipe2  = "|zsh"                       ascii
        $pipe3  = "| bash"                     ascii
        $pipe4  = "| sh"                       ascii

        $curl   = "curl -s"                    ascii

    condition:
        ( any of ($eval*) and any of ($b64*) )
        or
        ( $curl and any of ($b64*) and any of ($pipe*) )
}
