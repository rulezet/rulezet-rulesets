import "pe"
rule cert_blocklist_c1a1db95d7bf80290aa6e82d8f8f996a {
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
            pe.signatures[i].subject contains "Software Two Pty Ltd" and (
                pe.signatures[i].serial == "00:c1:a1:db:95:d7:bf:80:29:0a:a6:e8:2d:8f:8f:99:6a" or
                pe.signatures[i].serial == "c1:a1:db:95:d7:bf:80:29:0a:a6:e8:2d:8f:8f:99:6a"
            ) and
            1615334400 <= pe.signatures[i].not_after
        )
}