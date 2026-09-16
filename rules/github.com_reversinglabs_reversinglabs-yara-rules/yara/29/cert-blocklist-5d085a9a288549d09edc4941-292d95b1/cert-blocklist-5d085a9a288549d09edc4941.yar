import "pe"
rule cert_blocklist_5d085a9a288549d09edc4941 {
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
            pe.signatures[i].serial == "5d:08:5a:9a:28:85:49:d0:9e:dc:49:41" and
            1478757821 <= pe.signatures[i].not_after
        )
}