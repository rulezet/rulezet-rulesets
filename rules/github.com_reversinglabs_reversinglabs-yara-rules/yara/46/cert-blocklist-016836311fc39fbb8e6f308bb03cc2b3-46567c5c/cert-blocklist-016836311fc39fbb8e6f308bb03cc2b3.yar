import "pe"
rule cert_blocklist_016836311fc39fbb8e6f308bb03cc2b3 {
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
            pe.signatures[i].subject contains "SERVICE STREAM LIMITED" and
            pe.signatures[i].serial == "01:68:36:31:1f:c3:9f:bb:8e:6f:30:8b:b0:3c:c2:b3" and
            1602547200 <= pe.signatures[i].not_after
        )
}