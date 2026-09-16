import "pe"
rule cert_blocklist_052242ace583adf2a3b96adcb04d0812 {
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
            pe.signatures[i].subject contains "FAN-CHAI, TOV" and
            pe.signatures[i].serial == "05:22:42:ac:e5:83:ad:f2:a3:b9:6a:dc:b0:4d:08:12" and
            1573603200 <= pe.signatures[i].not_after
        )
}