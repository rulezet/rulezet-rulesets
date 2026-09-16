import "pe"
rule cert_blocklist_5a17d5de74fd8f09df596df3123139bb {
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
            pe.signatures[i].subject contains "ACTA FIS d.o.o." and
            pe.signatures[i].serial == "5a:17:d5:de:74:fd:8f:09:df:59:6d:f3:12:31:39:bb" and
            1611273600 <= pe.signatures[i].not_after
        )
}