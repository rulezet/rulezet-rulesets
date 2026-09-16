import "pe"
rule cert_blocklist_6fc143ba34cabf1de7a4c7f8f4cdad6d {
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
            pe.signatures[i].subject contains "World Telecom International Inc." and
            pe.signatures[i].serial == "6f:c1:43:ba:34:ca:bf:1d:e7:a4:c7:f8:f4:cd:ad:6d" and
            1147046400 <= pe.signatures[i].not_after
        )
}