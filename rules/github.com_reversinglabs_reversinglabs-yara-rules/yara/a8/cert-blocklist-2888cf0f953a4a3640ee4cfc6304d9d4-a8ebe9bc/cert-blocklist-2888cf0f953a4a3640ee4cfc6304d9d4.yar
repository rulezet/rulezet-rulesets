import "pe"
rule cert_blocklist_2888cf0f953a4a3640ee4cfc6304d9d4 {
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
            pe.signatures[i].subject contains "Lotte Schmidt" and
            pe.signatures[i].serial == "28:88:cf:0f:95:3a:4a:36:40:ee:4c:fc:63:04:d9:d4" and
            1608024974 <= pe.signatures[i].not_after
        )
}