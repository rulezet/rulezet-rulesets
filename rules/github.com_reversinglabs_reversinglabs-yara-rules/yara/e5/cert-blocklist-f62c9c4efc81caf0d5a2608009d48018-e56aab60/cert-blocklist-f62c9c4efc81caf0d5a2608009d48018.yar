import "pe"
rule cert_blocklist_f62c9c4efc81caf0d5a2608009d48018 {
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
            pe.signatures[i].subject contains "\\xE5\\x94\\x90\\xE5\\xB1\\xB1\\xE4\\xB8\\x87\\xE4\\xB8\\x9C\\xE6\\xB6\\xA6\\xE6\\x92\\xAD\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (
                pe.signatures[i].serial == "00:f6:2c:9c:4e:fc:81:ca:f0:d5:a2:60:80:09:d4:80:18" or
                pe.signatures[i].serial == "f6:2c:9c:4e:fc:81:ca:f0:d5:a2:60:80:09:d4:80:18"
            ) and
            1292889599 <= pe.signatures[i].not_after
        )
}