/*
    Campaign-specific indicators -- macOS ClickFix, fake Cloudflare Turnstile
    First observed 2026-08-04, delivered via a compromised German school website.

    High selectivity: any hit here is this campaign. Safe to alert on directly.

    Scan targets: shell history (~/.zsh_history, ~/.bash_history), clipboard dumps,
    browser cache and HTML artefacts, memory dumps, quarantine metadata.
    NOT intended for Mach-O scanning.
*/

rule ClickFix_Campaign_Cloudflare_2026_08 : clickfix macos campaign
{
    meta:
        author       = "Novum Analytica GmbH"
        date         = "2026-08-04"
        yarahub_uuid                = "a015291f-f8ef-53b2-a3c9-c6a7f54fb760"
        yarahub_reference_md5       = "2169ff5e7be77fc3ff72758f9fa50658"
        yarahub_reference_link      = "https://github.com/raimurokko/macos-threat-tracking"
        yarahub_license             = "CC0 1.0"
        yarahub_rule_matching_tlp   = "TLP:WHITE"
        yarahub_rule_sharing_tlp    = "TLP:WHITE"
        description  = "ClickFix campaign infrastructure and clipboard markers, Aug 2026"
        reference    = "https://github.com/raimurokko/macos-threat-tracking"
        severity     = "critical"
        mitre_attack = "T1204.004, T1059.004, T1105"
        tlp          = "TLP:CLEAR"
        license      = "CC0-1.0"

    strings:
        // Attacker infrastructure
        $d1 = "enter-pverif-code.info"        ascii nocase
        $d2 = "ferncurrent14.com"             ascii nocase

        // Path components
        $t1 = "b143d2530595a6b8a52694418e2edbe35405383d15e3397923ce0c747c25cfab" ascii
        $t2 = "a7ec41c89a3dc6bf3de47264b4a3013134c7273dd1aa379859c2149b7517f0b2" ascii

        // Session marker prepended to the clipboard command
        $m1 = "_7dcf=af7d6e2e6aa1"            ascii

        // Base64-encoded forms as they appear in the clipboard payload,
        // before either decode layer is peeled off
        $b1 = "aHR0cHM6Ly9mZXJuY3VycmVudDE0LmNvbQ"      ascii
        $b2 = "aHR0cDovL2VudGVyLXB2ZXJpZi1jb2RlLmluZm8" ascii

    condition:
        any of them
}
