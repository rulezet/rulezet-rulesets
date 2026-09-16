import "pe"
rule cert_blocklist_383ca88d6d9379c740609560 {
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
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "38:3c:a8:8d:6d:93:79:c7:40:60:95:60" and
            1478250214 <= pe.signatures[i].not_after
        )
}