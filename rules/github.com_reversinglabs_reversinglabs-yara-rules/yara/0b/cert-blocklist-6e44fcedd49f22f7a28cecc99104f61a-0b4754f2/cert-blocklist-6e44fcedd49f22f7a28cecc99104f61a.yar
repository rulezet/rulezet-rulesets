import "pe"
rule cert_blocklist_6e44fcedd49f22f7a28cecc99104f61a {
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
            pe.signatures[i].subject contains "M-Trans Maciej Caban" and
            pe.signatures[i].serial == "6e:44:fc:ed:d4:9f:22:f7:a2:8c:ec:c9:91:04:f6:1a" and
            1672923378 <= pe.signatures[i].not_after
        )
}