import "pe"
rule cert_blocklist_aebe117a13b8bca21685df48c74f584d {
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
            pe.signatures[i].subject contains "NANAX d.o.o." and (
                pe.signatures[i].serial == "00:ae:be:11:7a:13:b8:bc:a2:16:85:df:48:c7:4f:58:4d" or
                pe.signatures[i].serial == "ae:be:11:7a:13:b8:bc:a2:16:85:df:48:c7:4f:58:4d"
            ) and
            1613520000 <= pe.signatures[i].not_after
        )
}