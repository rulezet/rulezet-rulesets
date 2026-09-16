import "pe"
rule cert_blocklist_6ded1a7ff6da152a98a57a2f {
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
            pe.signatures[i].serial == "6d:ed:1a:7f:f6:da:15:2a:98:a5:7a:2f" and
            1479094343 <= pe.signatures[i].not_after
        )
}