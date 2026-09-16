import "pe"
rule cert_blocklist_f57df6a6eee3854d513d0ba8585049b7 {
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
            pe.signatures[i].subject contains "smnetworks" and (
                pe.signatures[i].serial == "00:f5:7d:f6:a6:ee:e3:85:4d:51:3d:0b:a8:58:50:49:b7" or
                pe.signatures[i].serial == "f5:7d:f6:a6:ee:e3:85:4d:51:3d:0b:a8:58:50:49:b7"
            ) and
            1277769600 <= pe.signatures[i].not_after
        )
}