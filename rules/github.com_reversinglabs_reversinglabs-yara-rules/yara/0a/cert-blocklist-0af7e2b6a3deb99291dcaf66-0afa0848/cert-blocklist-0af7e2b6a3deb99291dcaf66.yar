import "pe"
rule cert_blocklist_0af7e2b6a3deb99291dcaf66 {
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
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "0a:f7:e2:b6:a3:de:b9:92:91:dc:af:66" and
            1474523112 <= pe.signatures[i].not_after
        )
}