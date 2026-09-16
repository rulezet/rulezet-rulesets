import "pe"
rule cert_blocklist_fe9404dc73cf1c2ba1450b8398305557 {
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
            pe.signatures[i].subject contains "\\xE5\\x8E\\xA6\\xE9\\x97\\xA8\\xE7\\xBF\\x94\\xE9\\x80\\x9A\\xE4\\xBF\\xA1\\xE6\\x81\\xAF\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8\\xE5\\x8C\\x97\\xE4\\xBA\\xAC\\xE5\\x88\\x86\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (
                pe.signatures[i].serial == "00:fe:94:04:dc:73:cf:1c:2b:a1:45:0b:83:98:30:55:57" or
                pe.signatures[i].serial == "fe:94:04:dc:73:cf:1c:2b:a1:45:0b:83:98:30:55:57"
            ) and
            1287360000 <= pe.signatures[i].not_after
        )
}