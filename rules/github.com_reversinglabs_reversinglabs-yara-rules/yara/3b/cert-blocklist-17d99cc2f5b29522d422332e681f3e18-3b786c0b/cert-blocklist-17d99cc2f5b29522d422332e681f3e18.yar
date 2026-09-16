import "pe"
rule cert_blocklist_17d99cc2f5b29522d422332e681f3e18 {
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
            pe.signatures[i].subject contains "PKV Trading ApS" and
            pe.signatures[i].serial == "17:d9:9c:c2:f5:b2:95:22:d4:22:33:2e:68:1f:3e:18" and
            1613088000 <= pe.signatures[i].not_after
        )
}