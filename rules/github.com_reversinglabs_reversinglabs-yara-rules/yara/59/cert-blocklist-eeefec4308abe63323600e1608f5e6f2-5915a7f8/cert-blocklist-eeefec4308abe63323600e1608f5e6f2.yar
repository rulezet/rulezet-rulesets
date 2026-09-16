import "pe"
rule cert_blocklist_eeefec4308abe63323600e1608f5e6f2 {
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
            pe.signatures[i].subject contains "YUPITER-STROI, OOO" and (
                pe.signatures[i].serial == "00:ee:ef:ec:43:08:ab:e6:33:23:60:0e:16:08:f5:e6:f2" or
                pe.signatures[i].serial == "ee:ef:ec:43:08:ab:e6:33:23:60:0e:16:08:f5:e6:f2"
            ) and
            1491177600 <= pe.signatures[i].not_after
        )
}