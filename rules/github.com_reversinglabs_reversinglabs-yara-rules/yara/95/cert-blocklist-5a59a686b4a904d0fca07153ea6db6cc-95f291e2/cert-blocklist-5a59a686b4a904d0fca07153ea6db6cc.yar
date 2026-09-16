import "pe"
rule cert_blocklist_5a59a686b4a904d0fca07153ea6db6cc {
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
            pe.signatures[i].subject contains "ABADAN PIZZA LTD" and
            pe.signatures[i].serial == "5a:59:a6:86:b4:a9:04:d0:fc:a0:71:53:ea:6d:b6:cc" and
            1563403380 <= pe.signatures[i].not_after
        )
}