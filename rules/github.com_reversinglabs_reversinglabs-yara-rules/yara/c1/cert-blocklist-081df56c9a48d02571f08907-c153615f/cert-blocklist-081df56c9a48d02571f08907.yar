import "pe"
rule cert_blocklist_081df56c9a48d02571f08907 {
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
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "08:1d:f5:6c:9a:48:d0:25:71:f0:89:07" and
            1474870728 <= pe.signatures[i].not_after
        )
}