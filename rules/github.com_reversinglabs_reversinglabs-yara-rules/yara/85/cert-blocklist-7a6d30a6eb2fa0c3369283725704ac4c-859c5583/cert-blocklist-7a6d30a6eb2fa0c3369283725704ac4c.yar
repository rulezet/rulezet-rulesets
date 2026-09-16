import "pe"
rule cert_blocklist_7a6d30a6eb2fa0c3369283725704ac4c {
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
            pe.signatures[i].subject contains "Trade By International ApS" and
            pe.signatures[i].serial == "7a:6d:30:a6:eb:2f:a0:c3:36:92:83:72:57:04:ac:4c" and
            1619568000 <= pe.signatures[i].not_after
        )
}