import "pe"
rule cert_blocklist_1be41b34127ca9e6270830d2070db426 {
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
            pe.signatures[i].subject contains "\\xE5\\x8C\\x97\\xE4\\xBA\\xAC\\xE8\\x80\\x98\\xE5\\x8D\\x87\\xE5\\xA4\\xA9\\xE4\\xB8\\x8B\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "1b:e4:1b:34:12:7c:a9:e6:27:08:30:d2:07:0d:b4:26" and
            1352764799 <= pe.signatures[i].not_after
        )
}