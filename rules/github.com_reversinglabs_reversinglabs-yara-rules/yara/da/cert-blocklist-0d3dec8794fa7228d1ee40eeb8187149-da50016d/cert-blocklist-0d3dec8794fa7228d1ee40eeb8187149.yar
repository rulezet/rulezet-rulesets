import "pe"
rule cert_blocklist_0d3dec8794fa7228d1ee40eeb8187149 {
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
            pe.signatures[i].subject contains "Financial Security Institute, Inc." and
            pe.signatures[i].serial == "0d:3d:ec:87:94:fa:72:28:d1:ee:40:ee:b8:18:71:49" and
            1582675200 <= pe.signatures[i].not_after
        )
}