import "pe"
rule cert_blocklist_37a67cf754ee5ae284b4cf8b9d651604 {
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
            pe.signatures[i].subject contains "FORTH PROPERTY LTD" and
            pe.signatures[i].serial == "37:a6:7c:f7:54:ee:5a:e2:84:b4:cf:8b:9d:65:16:04" and
            1617321600 <= pe.signatures[i].not_after
        )
}