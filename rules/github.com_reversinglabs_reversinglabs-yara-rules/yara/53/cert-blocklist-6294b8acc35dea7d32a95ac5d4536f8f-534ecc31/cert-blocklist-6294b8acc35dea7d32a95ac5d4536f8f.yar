import "pe"
rule cert_blocklist_6294b8acc35dea7d32a95ac5d4536f8f {
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
            pe.signatures[i].subject contains "\\xE9\\x87\\x8D\\xE5\\xBA\\x86\\xE6\\x8E\\xA2\\xE9\\x95\\xBF\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "62:94:b8:ac:c3:5d:ea:7d:32:a9:5a:c5:d4:53:6f:8f" and
            1517443200 <= pe.signatures[i].not_after
        )
}