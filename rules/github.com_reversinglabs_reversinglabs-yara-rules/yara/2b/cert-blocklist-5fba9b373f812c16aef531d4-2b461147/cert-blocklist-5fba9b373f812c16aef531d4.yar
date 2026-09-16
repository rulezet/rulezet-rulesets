import "pe"
rule cert_blocklist_5fba9b373f812c16aef531d4 {
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
            pe.signatures[i].serial == "5f:ba:9b:37:3f:81:2c:16:ae:f5:31:d4" and
            1473329076 <= pe.signatures[i].not_after
        )
}