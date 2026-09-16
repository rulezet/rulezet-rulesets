rule cecilio_botnet
{
    meta:
        author = "Nokia Deepfield ERT"
        description = "Cecilio botnet - CatDDoS derivative with modified RC4 table encryption"
        reference = "https://blog.xlab.qianxin.com/catddos-derivative-en/"
        date = "2026-03-09"
        family = "cecilio"
        severity = "high"
        yarahub_uuid = "28c1ad64-c553-4358-9d89-84472251d3b6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a6758a2eac67b6e2fbe4c3ee4f3e4b7c"

    strings:
                        $rc4_key = { c9 ba 3e 11 4f 2a 7d e0 e6 8d bb eb 9a 87 87 7e }

                        $reg_magic = { 56 63 34 86 90 69 21 01 }

                $cred_pon = "Pon521"
        $cred_zte = "Zte521"
        $cred_root621 = "root621"
        $cred_zxic = "Zxic521"
        $cred_wabjtam = "wabjtam"
        $cred_tsgoingon = "tsgoingon"

                $fastcat = "/bin/busybox FASTCAT"

                $snquery = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"

                $vse = "TSource Engine Query"

    condition:
        uint32(0) == 0x464c457f and          (
                        $rc4_key or

                        $reg_magic or

                                    ($reg_magic and $fastcat and 3 of ($cred_*)) or

                        ($reg_magic and 3 of ($cred_*) and ($vse or $snquery))
        )
}