import "pe"
rule cert_blocklist_a3e62be1572293ad618f58a8aa32857f {
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
            pe.signatures[i].subject contains "ISIDA, TOV" and (
                pe.signatures[i].serial == "00:a3:e6:2b:e1:57:22:93:ad:61:8f:58:a8:aa:32:85:7f" or
                pe.signatures[i].serial == "a3:e6:2b:e1:57:22:93:ad:61:8f:58:a8:aa:32:85:7f"
            ) and
            1596585600 <= pe.signatures[i].not_after
        )
}