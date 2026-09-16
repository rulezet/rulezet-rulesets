import "pe"
rule cert_blocklist_4b03cabe6a0481f17a2dbeb9aefad425 {
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
            pe.signatures[i].subject contains "RASSVET, OOO" and
            pe.signatures[i].serial == "4b:03:ca:be:6a:04:81:f1:7a:2d:be:b9:ae:fa:d4:25" and
            1603230930 <= pe.signatures[i].not_after
        )
}