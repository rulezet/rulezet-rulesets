import "pe"
rule cert_blocklist_202cf8 {
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
            pe.signatures[i].subject contains "DATALINE LTD." and
            pe.signatures[i].serial == "20:2c:f8" and
            1087841761 <= pe.signatures[i].not_after
        )
}