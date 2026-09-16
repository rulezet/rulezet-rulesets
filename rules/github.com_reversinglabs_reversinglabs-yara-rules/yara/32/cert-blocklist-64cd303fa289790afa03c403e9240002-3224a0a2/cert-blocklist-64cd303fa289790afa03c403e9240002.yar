import "pe"
rule cert_blocklist_64cd303fa289790afa03c403e9240002 {
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
            pe.signatures[i].subject contains "MAITLAND TRIFECTA, INC." and 
            pe.signatures[i].serial == "64:cd:30:3f:a2:89:79:0a:fa:03:c4:03:e9:24:00:02" and
            1602723600 <= pe.signatures[i].not_after
        )
}