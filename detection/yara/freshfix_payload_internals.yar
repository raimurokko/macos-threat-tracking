/*
    freshfix loader - key schedule constants, decrypted payload, runtime artefacts

    Written 2026-08-07 after the stage-3 blob was decrypted. See
    campaigns/2026-08-04-cloudflare-clickfix/stage4_payload.md.

    Three rules, and they are deliberately aimed at three different scan targets,
    because the interesting strings live in three different places:

      1. FreshFix_Loader_KeySchedule
         File scan against the Mach-O. Anchors on the PBKDF2 iteration count, which
         is baked into the instruction stream of both slices. A build with different
         keys still uses the same iteration count, because that comes from the
         packer, not from the per-build key material.

      2. FreshFix_Payload_AppleScript
         File scan against the *decrypted* payload, for anyone who repeats the
         decryption or receives the plaintext. Also matches in memory.

      3. FreshFix_Loader_AntiAnalysis_Memory
         MEMORY SCAN ONLY. The analyst-tool blacklist is XOR-encrypted per fragment
         in the file and only assembles at runtime, so a file scan cannot see it.
         Against a live process or a core dump it is a very strong signal.

    Note on the plaintext HKDF labels: only "freshfix.bootstrap" is present in both
    slices. "hwval-frag" and "freshfix-frag" appear in the arm64 slice only. Any rule
    requiring all three matches ARM builds and silently misses Intel ones.

    Reference loader  : SHA256 29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40
    Reference payload : SHA256 95ab5a61a0970410ada36ba843e55e270f38cb8e2eebf79254434948e11c870f
*/

rule FreshFix_Loader_KeySchedule : clickfix macos loader macho freshfix
{
    meta:
        author       = "Novum Analytica GmbH"
        date         = "2026-08-07"
        description  = "freshfix packer: PBKDF2-HMAC-SHA256 key schedule with 98222 iterations, both slices"
        reference    = "https://github.com/raimurokko/macos-threat-tracking"
        severity     = "critical"
        mitre_attack = "T1027.009, T1620, T1497"
        tlp          = "TLP:CLEAR"
        license      = "CC0-1.0"
        note         = "The iteration count is a packer constant, not a per-build key. Survives rekeying; would not survive a packer version change."

    strings:
        // arm64:  mov w8, #0x7fae ; movk w8, #0x1, lsl #16     -> 98222
        $it_arm = { c8 f5 8f 52 28 00 a0 72 }

        // x86_64: cmpl $0x17fae, %ebx                          -> 98222
        $it_x64 = { 81 fb ae 7f 01 00 }

        // Builder label, present in every slice seen so far.
        // "hwval-frag" and "freshfix-frag" are deliberately NOT required here:
        // they exist in the arm64 slice only, and requiring them would drop
        // Intel builds. See the file header.
        $lbl    = "freshfix.bootstrap" ascii

    condition:
        ( uint32be(0) == 0xcafebabe or uint32(0) == 0xfeedfacf or uint32be(0) == 0xcffaedfe )
        and filesize < 5MB
        and $lbl
        and any of ($it_*)
}

rule FreshFix_Payload_AppleScript : clickfix macos stealer applescript freshfix
{
    meta:
        author       = "Novum Analytica GmbH"
        date         = "2026-08-07"
        description  = "Decrypted freshfix stage-4 payload: run-only AppleScript stealer with root LaunchDaemon persistence and wallet application replacement"
        reference    = "https://github.com/raimurokko/macos-threat-tracking"
        severity     = "critical"
        mitre_attack = "T1059.002, T1543.004, T1555.001, T1552.001, T1074.001, T1657"
        tlp          = "TLP:CLEAR"
        license      = "CC0-1.0"
        note         = "Literals are UTF-16BE, hence the wide modifier. Matches the plaintext, not the shipped Mach-O."

    strings:
        $hdr    = "FasdUAS"                                     ascii

        // Staging directory, an AMOS-family hallmark
        $stage1 = "FileGrabber/"                                wide
        $stage2 = "NotesMedia/"                                 wide

        // Local password validation before the phished credential is used
        $auth   = "dscl . authonly"                             wide

        // Chrome Safe Storage extraction
        $safe   = "find-generic-password"                       wide

        // Root persistence, both daemons
        $per1   = ".com.apple.accountsd"                        wide
        $per2   = ".com.apple.metadata.mds"                     wide
        $per3   = "sudo -S launchctl bootstrap system"          wide

        // Second-stage and trojanised-wallet download path
        $zxc1   = "/zxc/kito"                                   wide
        $zxc2   = "/zxc/mdw"                                    wide
        $zxc3   = "/zxc/appex.zip"                              wide

        // Exfiltration
        $exf1   = "ditto -c -k --sequesterRsrc"                 wide
        $exf2   = "file=@/tmp/out.zip"                          wide
        $exf3   = "X-Partial: 1"                                wide

        // Phishing dialog
        $dlg    = "You need to configure system settings before running this application." wide

    condition:
        filesize < 2MB
        and $hdr at 0
        and (
            $dlg
            or 2 of ($per*)
            or 2 of ($zxc*)
            or ( any of ($stage*) and any of ($exf*) )
            or ( $auth and $safe )
        )
}

rule FreshFix_Loader_AntiAnalysis_Memory : clickfix macos loader freshfix memory
{
    meta:
        author       = "Novum Analytica GmbH"
        date         = "2026-08-07"
        description  = "freshfix analyst-tool blacklist, assembled in memory at runtime - MEMORY SCAN ONLY, cannot match a file on disk"
        reference    = "https://github.com/raimurokko/macos-threat-tracking"
        severity     = "high"
        mitre_attack = "T1497, T1622, T1518.001"
        tlp          = "TLP:CLEAR"
        license      = "CC0-1.0"
        note         = "These strings are XOR-encrypted per fragment in the Mach-O. A file scan will never hit. Intended for live-process or core-dump scanning. Recovered by emulation, see stage4_payload.md."

    strings:
        $t01 = "lldb-rpc-server"    ascii
        $t02 = "debugserver"        ascii
        $t03 = "frida-server"       ascii
        $t04 = "frida-trace"        ascii
        $t05 = "FridaGadget"        ascii
        $t06 = "MobileSubstrate"    ascii
        $t07 = "libcycript"         ascii
        $t08 = "binaryninja"        ascii
        $t09 = "class-dump"         ascii
        $t10 = "mitmproxy"          ascii
        $t11 = "Proxyman"           ascii
        $t12 = "jtool2"             ascii
        $t13 = "fs_usage"           ascii
        $t14 = "SBInjector"         ascii
        $t15 = "objection"          ascii

        $e1  = "MallocStackLoggingNoCompact" ascii
        $e2  = "DYLD_FORCE_FLAT_NAMESPACE"   ascii
        $e3  = "DYLD_PRINT_INITIALIZERS"     ascii
        $e4  = "NSZombieEnabled"             ascii

    condition:
        8 of ($t*) and 2 of ($e*)
}
