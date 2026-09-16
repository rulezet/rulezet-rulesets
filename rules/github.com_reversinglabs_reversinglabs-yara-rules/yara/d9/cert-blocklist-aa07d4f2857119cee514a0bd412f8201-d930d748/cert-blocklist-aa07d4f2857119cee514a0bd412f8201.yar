import "pe"
rule cert_blocklist_aa07d4f2857119cee514a0bd412f8201 {
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
            pe.signatures[i].subject contains "HANGA GIP d.o.o." and (
                pe.signatures[i].serial == "00:aa:07:d4:f2:85:71:19:ce:e5:14:a0:bd:41:2f:82:01" or
                pe.signatures[i].serial == "aa:07:d4:f2:85:71:19:ce:e5:14:a0:bd:41:2f:82:01"
            ) and
            1615766400 <= pe.signatures[i].not_after
        )
}