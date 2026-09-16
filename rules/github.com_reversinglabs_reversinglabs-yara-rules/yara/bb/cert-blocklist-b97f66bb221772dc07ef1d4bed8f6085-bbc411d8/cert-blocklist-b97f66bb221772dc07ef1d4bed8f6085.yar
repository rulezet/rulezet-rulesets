import "pe"
rule cert_blocklist_b97f66bb221772dc07ef1d4bed8f6085 {
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
            pe.signatures[i].subject contains "S-PRO d.o.o." and (
                pe.signatures[i].serial == "00:b9:7f:66:bb:22:17:72:dc:07:ef:1d:4b:ed:8f:60:85" or
                pe.signatures[i].serial == "b9:7f:66:bb:22:17:72:dc:07:ef:1d:4b:ed:8f:60:85"
            ) and
            1614556800 <= pe.signatures[i].not_after
        )
}