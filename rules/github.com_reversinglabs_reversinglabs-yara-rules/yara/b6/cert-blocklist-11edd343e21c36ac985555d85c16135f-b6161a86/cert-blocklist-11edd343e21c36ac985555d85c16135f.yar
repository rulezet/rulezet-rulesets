import "pe"
rule cert_blocklist_11edd343e21c36ac985555d85c16135f {
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
            pe.signatures[i].subject contains "Pribyl Handels GmbH" and
            pe.signatures[i].serial == "11:ed:d3:43:e2:1c:36:ac:98:55:55:d8:5c:16:13:5f" and
            1589925600 <= pe.signatures[i].not_after
        )
}