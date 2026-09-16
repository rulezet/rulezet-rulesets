import "pe"
rule cert_blocklist_6716a9c195987d5cfe53a094779461e7 {
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
            pe.signatures[i].subject contains "Inter Technologies Ltd." and
            pe.signatures[i].serial == "67:16:a9:c1:95:98:7d:5c:fe:53:a0:94:77:94:61:e7" and
            1169424000 <= pe.signatures[i].not_after
        )
}