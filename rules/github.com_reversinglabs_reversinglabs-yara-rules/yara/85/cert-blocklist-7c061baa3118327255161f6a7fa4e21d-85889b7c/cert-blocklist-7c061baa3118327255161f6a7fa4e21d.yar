import "pe"
rule cert_blocklist_7c061baa3118327255161f6a7fa4e21d {
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
            pe.signatures[i].subject contains "YUTAKS, OOO" and (
                pe.signatures[i].serial == "00:7c:06:1b:aa:31:18:32:72:55:16:1f:6a:7f:a4:e2:1d" or
                pe.signatures[i].serial == "7c:06:1b:aa:31:18:32:72:55:16:1f:6a:7f:a4:e2:1d"
            ) and
            1599611338 <= pe.signatures[i].not_after
        )
}