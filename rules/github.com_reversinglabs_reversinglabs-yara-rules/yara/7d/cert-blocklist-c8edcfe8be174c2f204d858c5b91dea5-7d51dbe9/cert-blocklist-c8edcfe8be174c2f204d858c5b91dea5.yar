import "pe"
rule cert_blocklist_c8edcfe8be174c2f204d858c5b91dea5 {
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
            pe.signatures[i].subject contains "Paarcopy Oy" and (
                pe.signatures[i].serial == "00:c8:ed:cf:e8:be:17:4c:2f:20:4d:85:8c:5b:91:de:a5" or
                pe.signatures[i].serial == "c8:ed:cf:e8:be:17:4c:2f:20:4d:85:8c:5b:91:de:a5"
            ) and
            1608076800 <= pe.signatures[i].not_after
        )
}