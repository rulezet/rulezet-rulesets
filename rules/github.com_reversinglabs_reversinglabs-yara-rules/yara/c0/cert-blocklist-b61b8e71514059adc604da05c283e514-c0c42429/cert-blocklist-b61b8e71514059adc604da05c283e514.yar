import "pe"
rule cert_blocklist_b61b8e71514059adc604da05c283e514 {
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
            pe.signatures[i].subject contains "APP DIVISION ApS" and (
                pe.signatures[i].serial == "00:b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14" or
                pe.signatures[i].serial == "b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14"
            ) and
            1603328400 <= pe.signatures[i].not_after
        )
}