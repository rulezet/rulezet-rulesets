import "pe"
rule cert_blocklist_bebef5c533ce92efc402fab8605c43ec {
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
            pe.signatures[i].subject contains "OOO VEKTOR" and (
                pe.signatures[i].serial == "00:be:be:f5:c5:33:ce:92:ef:c4:02:fa:b8:60:5c:43:ec" or
                pe.signatures[i].serial == "be:be:f5:c5:33:ce:92:ef:c4:02:fa:b8:60:5c:43:ec"
            ) and
            1587513600 <= pe.signatures[i].not_after
        )
}