import "pe"
rule cert_blocklist_369a02e5d90b2649040e7f87 {
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
            pe.signatures[i].serial == "36:9a:02:e5:d9:0b:26:49:04:0e:7f:87" and
            1479094204 <= pe.signatures[i].not_after
        )
}