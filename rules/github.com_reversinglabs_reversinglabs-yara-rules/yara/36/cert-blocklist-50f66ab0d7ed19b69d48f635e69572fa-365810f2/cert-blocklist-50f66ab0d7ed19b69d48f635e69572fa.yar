import "pe"
rule cert_blocklist_50f66ab0d7ed19b69d48f635e69572fa {
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
            pe.signatures[i].subject contains "Wei Liu" and
            pe.signatures[i].serial == "50:f6:6a:b0:d7:ed:19:b6:9d:48:f6:35:e6:95:72:fa" and
            1467158400 <= pe.signatures[i].not_after
        )
}