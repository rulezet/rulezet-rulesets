import "pe"
rule cert_blocklist_4e0665d61997072294a70c662f72eae3 {
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
            pe.signatures[i].serial == "4e:06:65:d6:19:97:07:22:94:a7:0c:66:2f:72:ea:e3" and
            1474502400 <= pe.signatures[i].not_after
        )
}