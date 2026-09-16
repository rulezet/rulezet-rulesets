import "pe"
rule cert_blocklist_1380a7ccf2bf36bc496b00d8 {
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
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "13:80:a7:cc:f2:bf:36:bc:49:6b:00:d8" and
            1478069976 <= pe.signatures[i].not_after
        )
}