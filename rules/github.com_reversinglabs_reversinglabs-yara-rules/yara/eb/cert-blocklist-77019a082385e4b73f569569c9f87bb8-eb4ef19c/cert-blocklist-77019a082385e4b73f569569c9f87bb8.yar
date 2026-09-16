import "pe"
rule cert_blocklist_77019a082385e4b73f569569c9f87bb8 {
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
            pe.signatures[i].subject contains "AND LLC" and
            pe.signatures[i].serial == "77:01:9a:08:23:85:e4:b7:3f:56:95:69:c9:f8:7b:b8" and
            1308182400 <= pe.signatures[i].not_after
        )
}