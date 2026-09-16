import "pe"
rule cert_blocklist_0292c7d574132ba5c0441d1c7ffcb805 {
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
            pe.signatures[i].subject contains "TES LOGISTIKA d.o.o." and
            pe.signatures[i].serial == "02:92:c7:d5:74:13:2b:a5:c0:44:1d:1c:7f:fc:b8:05" and
            1602183720 <= pe.signatures[i].not_after
        )
}