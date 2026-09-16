import "pe"
rule cert_blocklist_3054f940c931bad7b238a24376c6a5cc {
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
            pe.signatures[i].subject contains "POLE CLEAN LTD" and
            pe.signatures[i].serial == "30:54:f9:40:c9:31:ba:d7:b2:38:a2:43:76:c6:a5:cc" and
            1637030220 <= pe.signatures[i].not_after
        )
}