import "pe"
rule cert_blocklist_0772b4d1d63233d2b8771997bc8da5c4 {
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
            pe.signatures[i].subject contains "Maya logistika d.o.o." and
            pe.signatures[i].serial == "07:72:b4:d1:d6:32:33:d2:b8:77:19:97:bc:8d:a5:c4" and
            1637971201 <= pe.signatures[i].not_after
        )
}