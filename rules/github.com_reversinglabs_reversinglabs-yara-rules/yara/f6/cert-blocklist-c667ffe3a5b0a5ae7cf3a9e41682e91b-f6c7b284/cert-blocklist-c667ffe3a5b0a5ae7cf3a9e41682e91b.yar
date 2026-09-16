import "pe"
rule cert_blocklist_c667ffe3a5b0a5ae7cf3a9e41682e91b {
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
            pe.signatures[i].subject contains "NAILS UNLIMITED LIMITED" and (
                pe.signatures[i].serial == "00:c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b" or
                pe.signatures[i].serial == "c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b"
            ) and
            1616976000 <= pe.signatures[i].not_after
        )
}