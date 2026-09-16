import "pe"
rule cert_blocklist_08aa03f385f870e3a6d243b74b1dadf6 {
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
            pe.signatures[i].subject contains "\\xE4\\xB8\\x9C\\xE8\\x8E\\x9E\\xE5\\xB8\\x82\\xE8\\x85\\xBE\\xE4\\xBA\\x91\\xE8\\xAE\\xA1\\xE7\\xAE\\x97\\xE6\\x9C\\xBA\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "08:aa:03:f3:85:f8:70:e3:a6:d2:43:b7:4b:1d:ad:f6" and
            1352678400 <= pe.signatures[i].not_after
        )
}