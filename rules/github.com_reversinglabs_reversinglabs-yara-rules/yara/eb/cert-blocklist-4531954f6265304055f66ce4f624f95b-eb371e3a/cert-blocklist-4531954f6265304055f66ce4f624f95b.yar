import "pe"
rule cert_blocklist_4531954f6265304055f66ce4f624f95b {
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
            pe.signatures[i].subject contains "IDAutomation.com" and
            pe.signatures[i].serial == "45:31:95:4f:62:65:30:40:55:f6:6c:e4:f6:24:f9:5b" and
            1384819199 <= pe.signatures[i].not_after
        )
}