import "pe"
rule cert_blocklist_6d633df9bb6015fc3ecea99dff309ee7 {
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
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "6d:63:3d:f9:bb:60:15:fc:3e:ce:a9:9d:ff:30:9e:e7" and
            1474156800 <= pe.signatures[i].not_after
        )
}