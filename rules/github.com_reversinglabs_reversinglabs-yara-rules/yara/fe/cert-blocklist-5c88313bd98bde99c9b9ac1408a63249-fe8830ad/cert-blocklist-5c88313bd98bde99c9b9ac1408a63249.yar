import "pe"
rule cert_blocklist_5c88313bd98bde99c9b9ac1408a63249 {
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
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "5c:88:31:3b:d9:8b:de:99:c9:b9:ac:14:08:a6:32:49" and
            1474243200 <= pe.signatures[i].not_after
        )
}