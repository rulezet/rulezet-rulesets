import "pe"
rule cert_blocklist_1f84e030a0ed10d5ffe2b81b {
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
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "1f:84:e0:30:a0:ed:10:d5:ff:e2:b8:1b" and
            1476869735 <= pe.signatures[i].not_after
        )
}