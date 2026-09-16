import "pe"
rule cert_blocklist_268c0d7028a154ac3b6349c5 {
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
            pe.signatures[i].serial == "26:8c:0d:70:28:a1:54:ac:3b:63:49:c5" and
            1474266712 <= pe.signatures[i].not_after
        )
}