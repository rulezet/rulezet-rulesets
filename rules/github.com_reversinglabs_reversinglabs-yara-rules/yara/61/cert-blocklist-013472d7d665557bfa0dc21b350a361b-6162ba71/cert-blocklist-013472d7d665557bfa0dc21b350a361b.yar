import "pe"
rule cert_blocklist_013472d7d665557bfa0dc21b350a361b {
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
            pe.signatures[i].subject contains "Yongli Zhang" and
            pe.signatures[i].serial == "01:34:72:d7:d6:65:55:7b:fa:0d:c2:1b:35:0a:36:1b" and
            1470960000 <= pe.signatures[i].not_after
        )
}