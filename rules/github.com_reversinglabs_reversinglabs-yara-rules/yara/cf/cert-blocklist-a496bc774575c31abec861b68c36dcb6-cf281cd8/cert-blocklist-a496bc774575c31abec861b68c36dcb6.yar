import "pe"
rule cert_blocklist_a496bc774575c31abec861b68c36dcb6 {
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
            pe.signatures[i].subject contains "ORGLE DVORSAK, d.o.o" and (
                pe.signatures[i].serial == "00:a4:96:bc:77:45:75:c3:1a:be:c8:61:b6:8c:36:dc:b6" or
                pe.signatures[i].serial == "a4:96:bc:77:45:75:c3:1a:be:c8:61:b6:8c:36:dc:b6"
            ) and
            1606867200 <= pe.signatures[i].not_after
        )
}