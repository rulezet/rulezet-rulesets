import "pe"
rule cert_blocklist_6a568f85de2061f67ded98707d4988df {
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
            pe.signatures[i].subject contains "OOO Apladis" and
            pe.signatures[i].serial == "6a:56:8f:85:de:20:61:f6:7d:ed:98:70:7d:49:88:df" and
            1613001600 <= pe.signatures[i].not_after
        )
}