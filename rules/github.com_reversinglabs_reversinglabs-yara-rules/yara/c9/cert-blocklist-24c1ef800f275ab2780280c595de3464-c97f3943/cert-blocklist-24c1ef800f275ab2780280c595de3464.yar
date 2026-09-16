import "pe"
rule cert_blocklist_24c1ef800f275ab2780280c595de3464 {
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
            pe.signatures[i].subject contains "HOLGAN LIMITED" and
            pe.signatures[i].serial == "24:c1:ef:80:0f:27:5a:b2:78:02:80:c5:95:de:34:64" and
            1614729600 <= pe.signatures[i].not_after
        )
}