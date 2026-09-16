import "pe"
rule cert_blocklist_684f478c7259dde0cfe2260112ca9846 {
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
            pe.signatures[i].subject contains "LLC \"IP EM\"" and
            pe.signatures[i].serial == "68:4f:47:8c:72:59:dd:e0:cf:e2:26:01:12:ca:98:46" and
            1584981648 <= pe.signatures[i].not_after
        )
}