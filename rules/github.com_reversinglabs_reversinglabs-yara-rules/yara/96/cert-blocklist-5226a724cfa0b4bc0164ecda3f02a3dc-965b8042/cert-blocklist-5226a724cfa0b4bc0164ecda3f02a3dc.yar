import "pe"
rule cert_blocklist_5226a724cfa0b4bc0164ecda3f02a3dc {
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
            pe.signatures[i].subject contains "VALENTE SP Z O O" and
            pe.signatures[i].serial == "52:26:a7:24:cf:a0:b4:bc:01:64:ec:da:3f:02:a3:dc" and
            1647302400 <= pe.signatures[i].not_after
        )
}