import "pe"
rule cert_blocklist_ed9caeb7911b31bd {
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
            pe.signatures[i].subject contains "\\xE4\\xB8\\x8A\\xE6\\xB5\\xB7\\xE5\\xA4\\xA9\\xE6\\xB8\\xB8\\xE8\\xBD\\xAF\\xE4\\xBB\\xB6\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (
                pe.signatures[i].serial == "00:ed:9c:ae:b7:91:1b:31:bd" or
                pe.signatures[i].serial == "ed:9c:ae:b7:91:1b:31:bd"
            ) and
            1506001740 <= pe.signatures[i].not_after
        )
}