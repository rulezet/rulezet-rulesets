import "pe"
rule cert_blocklist_4842afad00904ed8c98811e652ccb3b7 {
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
            pe.signatures[i].subject contains "\"VERY EXCLUSIVE LTD\"" and
            pe.signatures[i].serial == "48:42:af:ad:00:90:4e:d8:c9:88:11:e6:52:cc:b3:b7" and
            1545177600 <= pe.signatures[i].not_after
        )
}