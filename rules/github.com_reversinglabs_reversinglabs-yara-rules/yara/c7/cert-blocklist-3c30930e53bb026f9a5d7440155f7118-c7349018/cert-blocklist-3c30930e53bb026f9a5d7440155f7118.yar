import "pe"
rule cert_blocklist_3c30930e53bb026f9a5d7440155f7118 {
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
            pe.signatures[i].subject contains "CPM Media, Ltd." and
            pe.signatures[i].serial == "3c:30:93:0e:53:bb:02:6f:9a:5d:74:40:15:5f:71:18" and
            1064534400 <= pe.signatures[i].not_after
        )
}