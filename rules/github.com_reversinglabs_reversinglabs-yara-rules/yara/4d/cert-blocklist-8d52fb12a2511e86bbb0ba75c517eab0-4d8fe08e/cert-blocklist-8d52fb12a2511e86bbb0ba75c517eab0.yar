import "pe"
rule cert_blocklist_8d52fb12a2511e86bbb0ba75c517eab0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VThink Software Consulting Inc." and (
                pe.signatures[i].serial == "00:8d:52:fb:12:a2:51:1e:86:bb:b0:ba:75:c5:17:ea:b0" or
                pe.signatures[i].serial == "8d:52:fb:12:a2:51:1e:86:bb:b0:ba:75:c5:17:ea:b0"
            ) and
            1599177600 <= pe.signatures[i].not_after
        )
}