import "pe"
rule cert_blocklist_b0a308fc2e71ac4ac40677b9c27ccbad {
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
            pe.signatures[i].subject contains "Volpayk LLC" and (
                pe.signatures[i].serial == "00:b0:a3:08:fc:2e:71:ac:4a:c4:06:77:b9:c2:7c:cb:ad" or
                pe.signatures[i].serial == "b0:a3:08:fc:2e:71:ac:4a:c4:06:77:b9:c2:7c:cb:ad"
            ) and
            1611705600 <= pe.signatures[i].not_after
        )
}