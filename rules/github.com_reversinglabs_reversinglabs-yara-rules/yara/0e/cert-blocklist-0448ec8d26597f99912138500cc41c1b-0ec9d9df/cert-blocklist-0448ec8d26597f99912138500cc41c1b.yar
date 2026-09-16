import "pe"
rule cert_blocklist_0448ec8d26597f99912138500cc41c1b {
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
            pe.signatures[i].subject contains "\\xE5\\xA4\\xA7\\xE8\\xBF\\x9E\\xE7\\xBA\\xB5\\xE6\\xA2\\xA6\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "04:48:ec:8d:26:59:7f:99:91:21:38:50:0c:c4:1c:1b" and
            1585108595 <= pe.signatures[i].not_after
        )
}