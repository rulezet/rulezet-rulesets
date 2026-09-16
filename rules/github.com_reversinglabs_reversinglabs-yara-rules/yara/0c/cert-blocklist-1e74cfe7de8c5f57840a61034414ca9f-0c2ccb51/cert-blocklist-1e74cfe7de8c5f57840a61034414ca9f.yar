import "pe"
rule cert_blocklist_1e74cfe7de8c5f57840a61034414ca9f {
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
            pe.signatures[i].subject contains "Insta Software Solution Inc." and (
                pe.signatures[i].serial == "00:1e:74:cf:e7:de:8c:5f:57:84:0a:61:03:44:14:ca:9f" or
                pe.signatures[i].serial == "1e:74:cf:e7:de:8c:5f:57:84:0a:61:03:44:14:ca:9f"
            ) and
            1601733106 <= pe.signatures[i].not_after
        )
}