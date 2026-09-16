import "pe"
rule cert_blocklist_03b27d7f4ee21a462a064a17eef70d6c {
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
            pe.signatures[i].subject contains "CCL TRADING LIMITED" and
            pe.signatures[i].serial == "03:b2:7d:7f:4e:e2:1a:46:2a:06:4a:17:ee:f7:0d:6c" and
            1613952000 <= pe.signatures[i].not_after
        )
}