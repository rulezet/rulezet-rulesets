import "pe"
rule cert_blocklist_4beca26210737a5442ff8b47 {
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
            pe.signatures[i].serial == "4b:ec:a2:62:10:73:7a:54:42:ff:8b:47" and
            1476437049 <= pe.signatures[i].not_after
        )
}