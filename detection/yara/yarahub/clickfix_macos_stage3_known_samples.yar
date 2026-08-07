/*
    Known stage-3 loader build, campaign DANTE, 2026-08.
    One rule per file, because YARAhub accepts one rule per submission.

    Module-free since 2026-08-07. The previous version used hash.sha256() over the
    whole file, which requires the "hash" module to be compiled into the scanning
    YARA. That is not guaranteed - notably not on scanning services - and a rule
    that cannot load is worse than a rule that is slightly less exact.

    The replacement anchors on constants instead, and the main one is better than a
    file hash:

    __DATA_CONST+0xe0 (arm64) / +0xb0 (x86_64) holds the SHA-256 of the *decrypted
    payload*. The loader computes SHA-256 over the plaintext after decryption and
    compares it against this constant in constant time (arm64 +0x357c: XOR
    accumulate over 32 bytes, fold, branch) before executing it. It is the loader's
    own integrity check on its cargo.

    That makes it a better identifier than the file hash: it names the *payload*,
    so it still matches a rebuild of the loader around the same stealer - different
    file hash, different keys, same $payload_hash.

    Reference loader  : SHA256 29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40
    Reference payload : SHA256 95ab5a61a0970410ada36ba843e55e270f38cb8e2eebf79254434948e11c870f
    Reference: https://github.com/raimurokko/macos-threat-tracking
*/

rule ClickFix_macOS_Stage3_KnownSamples : clickfix macos campaign macho
{
    meta:
        author      = "Novum Analytica GmbH"
        date        = "2026-08-06"
        yarahub_uuid                = "b020502e-f647-417e-9d88-35e5a4ce2e9d"
        yarahub_reference_md5       = "ab477021780e553be4271cb34bb8394b"
        yarahub_reference_link      = "https://github.com/raimurokko/macos-threat-tracking"
        yarahub_license             = "CC0 1.0"
        yarahub_rule_matching_tlp   = "TLP:WHITE"
        yarahub_rule_sharing_tlp    = "TLP:WHITE"
        description = "Known stage-3 loader build, campaign DANTE, 2026-08. Anchored on the loader's stored SHA-256 of its own decrypted payload."
        reference   = "https://github.com/raimurokko/macos-threat-tracking"
        severity    = "critical"
        tlp         = "TLP:CLEAR"
        license     = "CC0-1.0"
        note        = "Module-free by design; requires no hash module. Matches the universal binary and both thin slices."

    strings:
        // SHA-256 of the decrypted stage-4 payload, stored for the loader's own
        // post-decryption integrity check. Present in both architecture slices.
        $payload_hash = {
            95 ab 5a 61 a0 97 04 10 ad a3 6b a8 43 e5 5e 27
            0f 38 cb 8e 2e eb f7 92 54 43 49 48 e1 1c 87 0f
        }

        // Per-build key material, arm64 slice: HKDF master key and 8-byte seed.
        $keymat_arm64 = {
            c6 ae e1 a1 91 31 ac 02 bd 15 89 70 3e 05 85 1f
            70 07 54 8c 03 ae ac f5 4a dc 2e ad 7d 04 f5 43
        }
        $seed_arm64 = { 34 25 96 cb 0d 6e 2d b9 }

        // Anti-tamper self-hash of __TEXT,__text, arm64 slice
        $selfhash_arm64 = {
            bd 52 c4 f4 b0 00 06 4d 64 db 27 ad 8c d6 40 39
            c8 e7 7d e2 0c 19 0f 9f b1 6a 88 14 97 63 41 05
        }

        // Builder label, both slices
        $label = "freshfix.bootstrap" ascii

    condition:
        ( uint32be(0) == 0xcafebabe or uint32(0) == 0xfeedfacf or uint32be(0) == 0xcffaedfe )
        and filesize < 5MB
        and $payload_hash
        and ( $label or any of ($keymat_arm64, $seed_arm64, $selfhash_arm64) )
}
