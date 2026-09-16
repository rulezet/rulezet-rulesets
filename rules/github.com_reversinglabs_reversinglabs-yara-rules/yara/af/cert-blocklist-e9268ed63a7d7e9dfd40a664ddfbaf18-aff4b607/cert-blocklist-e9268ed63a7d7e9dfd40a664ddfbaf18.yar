import "pe"
rule cert_blocklist_e9268ed63a7d7e9dfd40a664ddfbaf18 {
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
            pe.signatures[i].subject contains "Casta, s.r.o." and (
                pe.signatures[i].serial == "00:e9:26:8e:d6:3a:7d:7e:9d:fd:40:a6:64:dd:fb:af:18" or
                pe.signatures[i].serial == "e9:26:8e:d6:3a:7d:7e:9d:fd:40:a6:64:dd:fb:af:18"
            ) and
            1647302400 <= pe.signatures[i].not_after
        )
}