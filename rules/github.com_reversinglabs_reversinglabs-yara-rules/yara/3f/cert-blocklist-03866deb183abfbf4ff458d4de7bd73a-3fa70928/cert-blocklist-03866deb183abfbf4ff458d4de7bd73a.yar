import "pe"
rule cert_blocklist_03866deb183abfbf4ff458d4de7bd73a {
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
            pe.signatures[i].subject contains "\\xE9\\x87\\x8D\\xE5\\xBA\\x86\\xE8\\xAF\\x9D\\xE8\\xAF\\xAD\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "03:86:6d:eb:18:3a:bf:bf:4f:f4:58:d4:de:7b:d7:3a" and
            1371772799 <= pe.signatures[i].not_after
        )
}