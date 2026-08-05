/*
    ClickFix lure page.

    Identifies the HTML that drives the attack: a clipboard write combined with
    keyboard instructions pointing the visitor at Terminal.

    This is the rule that answers a site operator's actual question -- where is the
    injected script and what does it do. Run it over web root, CMS templates, database
    dumps and browser cache. Covers German and English wording.
*/

rule ClickFix_FakeCaptcha_Lure_Page : clickfix web lure
{
    meta:
        author       = "Novum Analytica GmbH"
        date         = "2026-08-04"
        description  = "ClickFix lure page: clipboard write plus Terminal instructions (DE/EN)"
        reference    = "https://github.com/raimurokko/macos-threat-tracking"
        severity     = "high"
        mitre_attack = "T1204.004, T1189"
        tlp          = "TLP:CLEAR"
        license      = "CC0-1.0"

    strings:
        $clip1 = "navigator.clipboard.writeText"  ascii nocase
        $clip2 = "document.execCommand('copy')"   ascii nocase
        $clip3 = "document.execCommand(\"copy\")" ascii nocase
        $clip4 = "ClipboardItem"                  ascii nocase

        $ins_de1 = "Menschliche Verifizierung"    ascii nocase
        $ins_de2 = "Ihrer Tastatur"               ascii nocase
        $ins_en1 = "Verify you are human"         ascii nocase
        $ins_en2 = "Press Command"                ascii nocase

        $key1 = "Terminal"                        ascii
        $key2 = "Command"                         ascii
        $key3 = "Space"                           ascii
        $key4 = "Enter"                           ascii

        $brand = "CLOUDFLARE"                     ascii nocase

    condition:
        filesize < 2MB
        and any of ($clip*)
        and all of ($key*)
        and ( any of ($ins_de*) or any of ($ins_en*) or $brand )
}
