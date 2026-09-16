import "pe"
rule cert_blocklist_5a364c4957d93406f76321c2316f42f0 {
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
            pe.signatures[i].subject contains "Board Game Bucket Ltd" and
            pe.signatures[i].serial == "5a:36:4c:49:57:d9:34:06:f7:63:21:c2:31:6f:42:f0" and
            1661337307 <= pe.signatures[i].not_after
        )
}