import "pe"
rule cert_blocklist_333705c20b56e57f60b5eb191eef0d90 {
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
            pe.signatures[i].subject contains "TASK Holding ApS" and
            pe.signatures[i].serial == "33:37:05:c2:0b:56:e5:7f:60:b5:eb:19:1e:ef:0d:90" and
            1634233052 <= pe.signatures[i].not_after
        )
}