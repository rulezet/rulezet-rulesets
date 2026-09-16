import "pe"
rule cert_blocklist_2f96a89bfec6e44dd224e8fd7e72d9bb {
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
            pe.signatures[i].subject contains "NAILS UNLIMITED LIMITED" and
            pe.signatures[i].serial == "2f:96:a8:9b:fe:c6:e4:4d:d2:24:e8:fd:7e:72:d9:bb" and
            1625529600 <= pe.signatures[i].not_after
        )
}