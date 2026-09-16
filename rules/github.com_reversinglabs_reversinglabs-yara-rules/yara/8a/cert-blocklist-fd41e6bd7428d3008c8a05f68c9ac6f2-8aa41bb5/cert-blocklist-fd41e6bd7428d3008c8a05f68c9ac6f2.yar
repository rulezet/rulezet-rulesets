import "pe"
rule cert_blocklist_fd41e6bd7428d3008c8a05f68c9ac6f2 {
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
            pe.signatures[i].subject contains "OM-FAS d.o.o." and (
                pe.signatures[i].serial == "00:fd:41:e6:bd:74:28:d3:00:8c:8a:05:f6:8c:9a:c6:f2" or
                pe.signatures[i].serial == "fd:41:e6:bd:74:28:d3:00:8c:8a:05:f6:8c:9a:c6:f2"
            ) and
            1575590400 <= pe.signatures[i].not_after
        )
}