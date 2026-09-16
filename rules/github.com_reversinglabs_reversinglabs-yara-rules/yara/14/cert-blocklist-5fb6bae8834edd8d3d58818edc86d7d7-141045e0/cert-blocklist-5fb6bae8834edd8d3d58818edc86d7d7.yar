import "pe"
rule cert_blocklist_5fb6bae8834edd8d3d58818edc86d7d7 {
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
            pe.signatures[i].subject contains "Tramplink LLC" and
            pe.signatures[i].serial == "5f:b6:ba:e8:83:4e:dd:8d:3d:58:81:8e:dc:86:d7:d7" and
            1600781989 <= pe.signatures[i].not_after
        )
}