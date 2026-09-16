import "pe"
rule cert_blocklist_063dcd7d7b0bc77cac844c7213be3989 {
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
            pe.signatures[i].subject contains "HANNAH SISK LIMITED" and
            pe.signatures[i].serial == "06:3d:cd:7d:7b:0b:c7:7c:ac:84:4c:72:13:be:39:89" and
            1656892801 <= pe.signatures[i].not_after
        )
}