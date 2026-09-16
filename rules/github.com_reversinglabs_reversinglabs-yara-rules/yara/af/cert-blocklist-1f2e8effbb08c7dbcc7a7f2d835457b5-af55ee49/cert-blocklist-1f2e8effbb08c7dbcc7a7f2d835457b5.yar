import "pe"
rule cert_blocklist_1f2e8effbb08c7dbcc7a7f2d835457b5 {
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
            pe.signatures[i].subject contains "RTI, OOO" and
            pe.signatures[i].serial == "1f:2e:8e:ff:bb:08:c7:db:cc:7a:7f:2d:83:54:57:b5" and
            1581382360 <= pe.signatures[i].not_after
        )
}