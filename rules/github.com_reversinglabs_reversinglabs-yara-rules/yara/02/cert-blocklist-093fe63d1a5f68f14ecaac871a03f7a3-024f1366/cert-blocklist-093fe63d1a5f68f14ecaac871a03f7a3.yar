import "pe"
rule cert_blocklist_093fe63d1a5f68f14ecaac871a03f7a3 {
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
            pe.signatures[i].subject contains "SPECTACLE IMAGE LTD" and
            pe.signatures[i].serial == "09:3f:e6:3d:1a:5f:68:f1:4e:ca:ac:87:1a:03:f7:a3" and
            1562716800 <= pe.signatures[i].not_after
        )
}