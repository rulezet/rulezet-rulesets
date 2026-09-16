import "pe"
rule cert_blocklist_014a98d697b44f43ded21f18eb6ad0ba {
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
            pe.signatures[i].subject contains "Hillcoe Software Inc." and
            pe.signatures[i].serial == "01:4a:98:d6:97:b4:4f:43:de:d2:1f:18:eb:6a:d0:ba" and
            1605364760 <= pe.signatures[i].not_after
        )
}