import "pe"
rule cert_blocklist_29128a56e7b3bfb230742591ac8b4718 {
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
            pe.signatures[i].subject contains "Programavimo paslaugos, MB" and
            pe.signatures[i].serial == "29:12:8a:56:e7:b3:bf:b2:30:74:25:91:ac:8b:47:18" and
            1590900909 <= pe.signatures[i].not_after
        )
}