import "pe"
rule cert_blocklist_3a6ccabb1c62f3be3eb03869fa43dc4a {
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
            pe.signatures[i].subject contains "\\xE5\\xB8\\xB8\\xE5\\xB7\\x9E\\xE9\\xAA\\x8F\\xE6\\x99\\xAF\\xE9\\x80\\x9A\\xE8\\x81\\x94\\xE6\\x95\\xB0\\xE5\\xAD\\x97\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "3a:6c:ca:bb:1c:62:f3:be:3e:b0:38:69:fa:43:dc:4a" and
            1259798399 <= pe.signatures[i].not_after
        )
}