import "pe"
rule cert_blocklist_523fb4036368dc26192d68827f2d889b {
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
            pe.signatures[i].subject contains "OOO MEDUZA SERVICE GROUP" and
            pe.signatures[i].serial == "52:3f:b4:03:63:68:dc:26:19:2d:68:82:7f:2d:88:9b" and
            1586847880 <= pe.signatures[i].not_after
        )
}