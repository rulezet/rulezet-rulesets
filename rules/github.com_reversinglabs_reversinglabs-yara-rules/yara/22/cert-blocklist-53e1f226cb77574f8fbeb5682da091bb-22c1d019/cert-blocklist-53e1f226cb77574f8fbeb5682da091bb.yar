import "pe"
rule cert_blocklist_53e1f226cb77574f8fbeb5682da091bb {
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
            pe.signatures[i].subject contains "OdyLab Inc" and
            pe.signatures[i].serial == "53:e1:f2:26:cb:77:57:4f:8f:be:b5:68:2d:a0:91:bb" and
            1654020559 <= pe.signatures[i].not_after
        )
}