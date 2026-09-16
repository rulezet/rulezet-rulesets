import "pe"
rule cert_blocklist_04d6b8cc6dce353fcf3ae8a532be7255 {
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
            pe.signatures[i].subject contains "MADERA" and
            pe.signatures[i].serial == "04:d6:b8:cc:6d:ce:35:3f:cf:3a:e8:a5:32:be:72:55" and
            1451692799 <= pe.signatures[i].not_after
        )
}