import "pe"
rule cert_blocklist_936bc256d2057ca9b9ec3034c3ed0ee6 {
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
            pe.signatures[i].subject contains "SALES & MAINTENANCE LIMITED" and (
                pe.signatures[i].serial == "00:93:6b:c2:56:d2:05:7c:a9:b9:ec:30:34:c3:ed:0e:e6" or
                pe.signatures[i].serial == "93:6b:c2:56:d2:05:7c:a9:b9:ec:30:34:c3:ed:0e:e6"
            ) and
            1616889600 <= pe.signatures[i].not_after
        )
}