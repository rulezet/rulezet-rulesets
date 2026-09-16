import "pe"
rule cert_blocklist_41d05676e0d31908be4dead3486aeae3 {
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
            pe.signatures[i].subject contains "Rov SP Z O O" and
            pe.signatures[i].serial == "41:d0:56:76:e0:d3:19:08:be:4d:ea:d3:48:6a:ea:e3" and
            1594857600 <= pe.signatures[i].not_after
        )
}