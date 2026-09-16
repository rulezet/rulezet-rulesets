import "pe"
rule cert_blocklist_5fe0ad6b03c57ab67a352159004ca3db {
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
            pe.signatures[i].subject contains "SpectorSoft Corp." and
            pe.signatures[i].serial == "5f:e0:ad:6b:03:c5:7a:b6:7a:35:21:59:00:4c:a3:db" and
            1402272000 <= pe.signatures[i].not_after
        )
}