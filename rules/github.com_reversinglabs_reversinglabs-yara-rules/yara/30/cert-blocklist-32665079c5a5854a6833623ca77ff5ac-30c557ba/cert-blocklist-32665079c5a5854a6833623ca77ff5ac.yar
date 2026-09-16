import "pe"
rule cert_blocklist_32665079c5a5854a6833623ca77ff5ac {
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
            pe.signatures[i].subject contains "Ohanae" and
            pe.signatures[i].serial == "32:66:50:79:c5:a5:85:4a:68:33:62:3c:a7:7f:f5:ac" and
            1381967999 <= pe.signatures[i].not_after
        )
}