import "pe"
rule cert_blocklist_2114ca3bd2afd63d7fa29d744992b043 {
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
            pe.signatures[i].subject contains "MATCH CONSULTANTS LTD" and
            pe.signatures[i].serial == "21:14:ca:3b:d2:af:d6:3d:7f:a2:9d:74:49:92:b0:43" and
            1625097600 <= pe.signatures[i].not_after
        )
}