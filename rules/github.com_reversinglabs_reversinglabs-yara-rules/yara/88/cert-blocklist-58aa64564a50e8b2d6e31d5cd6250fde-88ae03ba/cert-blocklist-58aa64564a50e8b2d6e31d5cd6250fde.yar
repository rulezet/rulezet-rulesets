import "pe"
rule cert_blocklist_58aa64564a50e8b2d6e31d5cd6250fde {
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
            pe.signatures[i].subject contains "Foreground" and
            pe.signatures[i].serial == "58:aa:64:56:4a:50:e8:b2:d6:e3:1d:5c:d6:25:0f:de" and
            1609002028 <= pe.signatures[i].not_after
        )
}