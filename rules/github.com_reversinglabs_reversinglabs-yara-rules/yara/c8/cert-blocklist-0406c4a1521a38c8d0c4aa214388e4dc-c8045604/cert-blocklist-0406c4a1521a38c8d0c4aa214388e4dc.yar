import "pe"
rule cert_blocklist_0406c4a1521a38c8d0c4aa214388e4dc {
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
            pe.signatures[i].subject contains "Venezia Design SRL" and
            pe.signatures[i].serial == "04:06:c4:a1:52:1a:38:c8:d0:c4:aa:21:43:88:e4:dc" and
            1641859201 <= pe.signatures[i].not_after
        )
}