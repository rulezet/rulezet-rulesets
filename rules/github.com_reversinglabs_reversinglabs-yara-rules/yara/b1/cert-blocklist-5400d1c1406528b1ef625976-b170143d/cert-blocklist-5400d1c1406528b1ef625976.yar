import "pe"
rule cert_blocklist_5400d1c1406528b1ef625976 {
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
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "54:00:d1:c1:40:65:28:b1:ef:62:59:76" and
            1474266628 <= pe.signatures[i].not_after
        )
}