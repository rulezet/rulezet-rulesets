import "pe"
rule cert_blocklist_e0134c41e7eda6863c4eee5b003976dd {
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
            pe.signatures[i].subject contains "5000 LIMITED" and (
                pe.signatures[i].serial == "00:e0:13:4c:41:e7:ed:a6:86:3c:4e:ee:5b:00:39:76:dd" or
                pe.signatures[i].serial == "e0:13:4c:41:e7:ed:a6:86:3c:4e:ee:5b:00:39:76:dd"
            ) and
            1528070400 <= pe.signatures[i].not_after
        )
}