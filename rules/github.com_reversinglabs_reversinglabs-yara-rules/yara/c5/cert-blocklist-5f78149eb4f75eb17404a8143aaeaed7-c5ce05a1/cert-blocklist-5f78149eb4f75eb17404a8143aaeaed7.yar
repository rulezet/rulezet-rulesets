import "pe"
rule cert_blocklist_5f78149eb4f75eb17404a8143aaeaed7 {
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
            pe.signatures[i].subject contains "\\xE4\\xB8\\x8A\\xE6\\xB5\\xB7\\xE5\\x9F\\x9F\\xE8\\x81\\x94\\xE8\\xBD\\xAF\\xE4\\xBB\\xB6\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "5f:78:14:9e:b4:f7:5e:b1:74:04:a8:14:3a:ae:ae:d7" and
            1303116124 <= pe.signatures[i].not_after
        )
}