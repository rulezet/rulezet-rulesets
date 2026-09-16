import "pe"
rule cert_blocklist_75cf729f8a740bbdef183a1c4d86a02f {
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
            pe.signatures[i].subject contains "Umbor LLC" and
            pe.signatures[i].serial == "75:cf:72:9f:8a:74:0b:bd:ef:18:3a:1c:4d:86:a0:2f" and
            1604223894 <= pe.signatures[i].not_after
        )
}