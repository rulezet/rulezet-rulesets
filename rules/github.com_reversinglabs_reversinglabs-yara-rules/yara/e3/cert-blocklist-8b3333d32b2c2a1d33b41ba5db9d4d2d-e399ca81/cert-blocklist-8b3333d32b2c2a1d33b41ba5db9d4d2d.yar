import "pe"
rule cert_blocklist_8b3333d32b2c2a1d33b41ba5db9d4d2d {
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
            pe.signatures[i].subject contains "BOOK CAF\\xC3\\x89, s.r.o." and (
                pe.signatures[i].serial == "00:8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d" or
                pe.signatures[i].serial == "8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d"
            ) and
            1620000000 <= pe.signatures[i].not_after
        )
}