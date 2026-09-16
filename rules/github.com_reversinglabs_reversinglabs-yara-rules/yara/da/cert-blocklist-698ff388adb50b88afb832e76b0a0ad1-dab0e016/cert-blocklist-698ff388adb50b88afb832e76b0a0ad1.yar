import "pe"
rule cert_blocklist_698ff388adb50b88afb832e76b0a0ad1 {
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
            pe.signatures[i].subject contains "BELLAP LIMITED" and
            pe.signatures[i].serial == "69:8f:f3:88:ad:b5:0b:88:af:b8:32:e7:6b:0a:0a:d1" and
            1675070541 <= pe.signatures[i].not_after
        )
}