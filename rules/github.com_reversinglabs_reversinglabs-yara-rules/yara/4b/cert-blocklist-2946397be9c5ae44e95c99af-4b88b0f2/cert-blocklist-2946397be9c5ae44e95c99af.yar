import "pe"
rule cert_blocklist_2946397be9c5ae44e95c99af {
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
            pe.signatures[i].serial == "29:46:39:7b:e9:c5:ae:44:e9:5c:99:af" and
            1476092708 <= pe.signatures[i].not_after
        )
}