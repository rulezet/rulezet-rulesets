import "pe"
rule cert_blocklist_13ae38c9ae21a8576c0d024d {
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
            pe.signatures[i].serial == "13:ae:38:c9:ae:21:a8:57:6c:0d:02:4d" and
            1475062802 <= pe.signatures[i].not_after
        )
}