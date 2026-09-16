import "pe"
rule cert_blocklist_0c4324ff41f0a7b16ffcc93dffa8fa99 {
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
            pe.signatures[i].subject contains "\\xE7\\xA6\\x8F\\xE5\\xBB\\xBA\\xE7\\x9C\\x81\\xE4\\xBA\\x94\\xE6\\x98\\x9F\\xE4\\xBF\\xA1\\xE6\\x81\\xAF\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "0c:43:24:ff:41:f0:a7:b1:6f:fc:c9:3d:ff:a8:fa:99" and
            1600300800 <= pe.signatures[i].not_after
        )
}