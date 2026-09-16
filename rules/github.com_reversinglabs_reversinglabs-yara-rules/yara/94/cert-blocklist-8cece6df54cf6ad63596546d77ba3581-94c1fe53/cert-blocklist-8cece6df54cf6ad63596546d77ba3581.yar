import "pe"
rule cert_blocklist_8cece6df54cf6ad63596546d77ba3581 {
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
            pe.signatures[i].subject contains "Mikael LLC" and (
                pe.signatures[i].serial == "00:8c:ec:e6:df:54:cf:6a:d6:35:96:54:6d:77:ba:35:81" or
                pe.signatures[i].serial == "8c:ec:e6:df:54:cf:6a:d6:35:96:54:6d:77:ba:35:81"
            ) and
            1613088000 <= pe.signatures[i].not_after
        )
}