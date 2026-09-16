import "pe"
rule cert_blocklist_172fea8cb06ffced6bfac7f2f6b77754 {
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
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "17:2f:ea:8c:b0:6f:fc:ed:6b:fa:c7:f2:f6:b7:77:54" and
            1467936000 <= pe.signatures[i].not_after
        )
}