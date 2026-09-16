import "pe"
rule cert_blocklist_29be2278113dd062eadca32de6b242d0 {
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
            pe.signatures[i].subject contains "BLADES" and
            pe.signatures[i].serial == "29:be:22:78:11:3d:d0:62:ea:dc:a3:2d:e6:b2:42:d0" and
            1536883200 <= pe.signatures[i].not_after
        )
}