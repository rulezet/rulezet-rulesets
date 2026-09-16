import "pe"
rule cert_blocklist_26f855a25890b749578f13e4b9459768 {
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
            pe.signatures[i].subject contains "Boo\\xE2\\x80\\x99s Q & Sweets Corporation" and
            pe.signatures[i].serial == "26:f8:55:a2:58:90:b7:49:57:8f:13:e4:b9:45:97:68" and
            1645401600 <= pe.signatures[i].not_after
        )
}