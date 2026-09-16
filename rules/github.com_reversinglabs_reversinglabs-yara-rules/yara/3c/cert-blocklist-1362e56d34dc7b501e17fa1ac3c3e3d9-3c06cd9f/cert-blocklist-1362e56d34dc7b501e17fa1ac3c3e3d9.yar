import "pe"
rule cert_blocklist_1362e56d34dc7b501e17fa1ac3c3e3d9 {
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
            pe.signatures[i].subject contains "OOO  \"Amaranth\"" and
            pe.signatures[i].serial == "13:62:e5:6d:34:dc:7b:50:1e:17:fa:1a:c3:c3:e3:d9" and
            1575936000 <= pe.signatures[i].not_after
        )
}