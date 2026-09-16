import "pe"
rule cert_blocklist_6ac6268b2e431a2c1369346d175d0e30 {
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
            pe.signatures[i].subject contains "Install Sync" and
            pe.signatures[i].serial == "6a:c6:26:8b:2e:43:1a:2c:13:69:34:6d:17:5d:0e:30" and
            1436140800 <= pe.signatures[i].not_after
        )
}