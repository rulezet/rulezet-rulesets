import "pe"
rule cert_blocklist_cc8d902da36587c9b2113cd76c3c3f8d {
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
            pe.signatures[i].subject contains "\\xE4\\xB8\\x8A\\xE6\\xB5\\xB7\\xE9\\x87\\x91\\xE4\\xBF\\x8A\\xE5\\x9D\\xA4\\xE8\\xAE\\xA1\\xE7\\xAE\\x97\\xE6\\x9C\\xBA\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x8D\\xE5\\x8A\\xA1\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (
                pe.signatures[i].serial == "00:cc:8d:90:2d:a3:65:87:c9:b2:11:3c:d7:6c:3c:3f:8d" or
                pe.signatures[i].serial == "cc:8d:90:2d:a3:65:87:c9:b2:11:3c:d7:6c:3c:3f:8d"
            ) and
            1292544000 <= pe.signatures[i].not_after
        )
}