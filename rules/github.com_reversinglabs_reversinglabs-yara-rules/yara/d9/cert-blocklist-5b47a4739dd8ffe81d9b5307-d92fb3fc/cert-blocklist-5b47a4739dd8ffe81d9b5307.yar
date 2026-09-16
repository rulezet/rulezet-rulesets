import "pe"
rule cert_blocklist_5b47a4739dd8ffe81d9b5307 {
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
            pe.signatures[i].serial == "5b:47:a4:73:9d:d8:ff:e8:1d:9b:53:07" and
            1476953007 <= pe.signatures[i].not_after
        )
}