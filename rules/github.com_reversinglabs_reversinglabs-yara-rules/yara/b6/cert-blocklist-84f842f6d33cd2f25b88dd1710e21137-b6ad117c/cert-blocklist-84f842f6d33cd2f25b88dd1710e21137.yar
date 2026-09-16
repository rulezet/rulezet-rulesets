import "pe"
rule cert_blocklist_84f842f6d33cd2f25b88dd1710e21137 {
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
            pe.signatures[i].subject contains "DataNext s.r.o." and (
                pe.signatures[i].serial == "00:84:f8:42:f6:d3:3c:d2:f2:5b:88:dd:17:10:e2:11:37" or
                pe.signatures[i].serial == "84:f8:42:f6:d3:3c:d2:f2:5b:88:dd:17:10:e2:11:37"
            ) and
            1586775720 <= pe.signatures[i].not_after
        )
}