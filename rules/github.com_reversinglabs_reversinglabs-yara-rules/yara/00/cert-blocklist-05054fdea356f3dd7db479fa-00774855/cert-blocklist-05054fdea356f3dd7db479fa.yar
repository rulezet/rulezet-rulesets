import "pe"
rule cert_blocklist_05054fdea356f3dd7db479fa {
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
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "05:05:4f:de:a3:56:f3:dd:7d:b4:79:fa" and
            1474436511 <= pe.signatures[i].not_after
        )
}