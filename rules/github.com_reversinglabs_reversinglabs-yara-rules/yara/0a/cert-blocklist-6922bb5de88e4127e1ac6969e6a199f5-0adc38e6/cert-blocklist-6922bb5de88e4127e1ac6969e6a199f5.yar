import "pe"
rule cert_blocklist_6922bb5de88e4127e1ac6969e6a199f5 {
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
            pe.signatures[i].subject contains "SMACHNA PLITKA, TOV" and
            pe.signatures[i].serial == "69:22:bb:5d:e8:8e:41:27:e1:ac:69:69:e6:a1:99:f5" and
            1552692162 <= pe.signatures[i].not_after
        )
}