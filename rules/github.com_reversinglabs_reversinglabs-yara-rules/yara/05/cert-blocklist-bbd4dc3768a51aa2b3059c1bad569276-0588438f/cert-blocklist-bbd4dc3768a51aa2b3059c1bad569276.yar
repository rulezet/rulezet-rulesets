import "pe"
rule cert_blocklist_bbd4dc3768a51aa2b3059c1bad569276 {
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
            pe.signatures[i].subject contains "JJ ELECTRICAL SERVICES LIMITED" and (
                pe.signatures[i].serial == "00:bb:d4:dc:37:68:a5:1a:a2:b3:05:9c:1b:ad:56:92:76" or
                pe.signatures[i].serial == "bb:d4:dc:37:68:a5:1a:a2:b3:05:9c:1b:ad:56:92:76"
            ) and
            1607472000 <= pe.signatures[i].not_after
        )
}