import "pe"
rule cert_blocklist_5b37ac3479283b6f9d75ddf0f8742d06 {
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
            pe.signatures[i].subject contains "ART BOOK PHOTO s.r.o." and
            pe.signatures[i].serial == "5b:37:ac:34:79:28:3b:6f:9d:75:dd:f0:f8:74:2d:06" and
            1619740800 <= pe.signatures[i].not_after
        )
}