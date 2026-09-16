import "pe"
rule cert_blocklist_b8164f7143e1a313003ab0c834562f1f {
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
            pe.signatures[i].subject contains "Ekitai Data Inc." and (
                pe.signatures[i].serial == "00:b8:16:4f:71:43:e1:a3:13:00:3a:b0:c8:34:56:2f:1f" or
                pe.signatures[i].serial == "b8:16:4f:71:43:e1:a3:13:00:3a:b0:c8:34:56:2f:1f"
            ) and
            1598313600 <= pe.signatures[i].not_after
        )
}