import "pe"
rule cert_blocklist_be77fe5c58b7a360add6a3fced4e8334 {
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
            pe.signatures[i].subject contains "Incar LLC" and (
                pe.signatures[i].serial == "00:be:77:fe:5c:58:b7:a3:60:ad:d6:a3:fc:ed:4e:83:34" or
                pe.signatures[i].serial == "be:77:fe:5c:58:b7:a3:60:ad:d6:a3:fc:ed:4e:83:34"
            ) and
            1602530730 <= pe.signatures[i].not_after
        )
}