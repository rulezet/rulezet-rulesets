import "pe"
rule cert_blocklist_256541e204619033f8b09f9eb7c88ef8 {
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
            pe.signatures[i].subject contains "HON HAI PRECISION INDUSTRY CO. LTD." and
            pe.signatures[i].serial == "25:65:41:e2:04:61:90:33:f8:b0:9f:9e:b7:c8:8e:f8" and
            1424303999 <= pe.signatures[i].not_after
        )
}