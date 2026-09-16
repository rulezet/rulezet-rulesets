import "pe"
rule cert_blocklist_02b6656292310b84022db5541bc48faf {
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
            pe.signatures[i].subject contains "DILA d.o.o." and
            pe.signatures[i].serial == "02:b6:65:62:92:31:0b:84:02:2d:b5:54:1b:c4:8f:af" and
            1613865600 <= pe.signatures[i].not_after
        )
}