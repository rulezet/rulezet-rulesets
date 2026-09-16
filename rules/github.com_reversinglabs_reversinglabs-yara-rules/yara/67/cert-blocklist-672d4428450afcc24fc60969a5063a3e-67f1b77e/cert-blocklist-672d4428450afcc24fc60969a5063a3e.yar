import "pe"
rule cert_blocklist_672d4428450afcc24fc60969a5063a3e {
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
            pe.signatures[i].subject contains "MEP, OOO" and
            pe.signatures[i].serial == "67:2d:44:28:45:0a:fc:c2:4f:c6:09:69:a5:06:3a:3e" and
            1597381260 <= pe.signatures[i].not_after
        )
}