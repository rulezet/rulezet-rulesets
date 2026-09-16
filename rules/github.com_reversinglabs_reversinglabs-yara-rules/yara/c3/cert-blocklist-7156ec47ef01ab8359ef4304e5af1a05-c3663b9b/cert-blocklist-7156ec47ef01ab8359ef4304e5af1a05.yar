import "pe"
rule cert_blocklist_7156ec47ef01ab8359ef4304e5af1a05 {
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
            pe.signatures[i].subject contains "BOREC, OOO" and
            pe.signatures[i].serial == "71:56:ec:47:ef:01:ab:83:59:ef:43:04:e5:af:1a:05" and
            1597363200 <= pe.signatures[i].not_after
        )
}