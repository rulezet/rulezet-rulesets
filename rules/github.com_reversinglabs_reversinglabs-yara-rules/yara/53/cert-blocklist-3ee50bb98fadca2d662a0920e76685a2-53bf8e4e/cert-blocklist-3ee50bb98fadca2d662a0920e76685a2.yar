import "pe"
rule cert_blocklist_3ee50bb98fadca2d662a0920e76685a2 {
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
            pe.signatures[i].subject contains "ABDULKADIR SAHIN" and
            pe.signatures[i].serial == "3e:e5:0b:b9:8f:ad:ca:2d:66:2a:09:20:e7:66:85:a2" and
            1330041600 <= pe.signatures[i].not_after
        )
}