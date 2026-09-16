import "pe"
rule cert_blocklist_4f3feb4baf377aea90a463c5dee63884 {
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
            pe.signatures[i].subject contains "F3D LIMITED" and
            pe.signatures[i].serial == "4f:3f:eb:4b:af:37:7a:ea:90:a4:63:c5:de:e6:38:84" and
            1526601599 <= pe.signatures[i].not_after
        )
}