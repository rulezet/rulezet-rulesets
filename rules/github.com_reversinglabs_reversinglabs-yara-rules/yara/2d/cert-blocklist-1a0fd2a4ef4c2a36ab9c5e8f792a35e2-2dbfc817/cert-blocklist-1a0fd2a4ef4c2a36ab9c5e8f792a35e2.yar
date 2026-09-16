import "pe"
rule cert_blocklist_1a0fd2a4ef4c2a36ab9c5e8f792a35e2 {
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
            pe.signatures[i].subject contains "\\xE5\\x8C\\x97\\xE4\\xBA\\xAC\\xE9\\x87\\x91\\xE5\\x88\\xA9\\xE5\\xAE\\x8F\\xE6\\x98\\x8C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "1a:0f:d2:a4:ef:4c:2a:36:ab:9c:5e:8f:79:2a:35:e2" and
            1389311999 <= pe.signatures[i].not_after
        )
}