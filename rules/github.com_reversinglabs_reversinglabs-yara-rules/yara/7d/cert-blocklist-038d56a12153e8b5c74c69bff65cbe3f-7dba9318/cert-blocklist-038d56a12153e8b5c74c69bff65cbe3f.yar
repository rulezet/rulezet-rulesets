import "pe"
rule cert_blocklist_038d56a12153e8b5c74c69bff65cbe3f {
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
            pe.signatures[i].subject contains "\\xE6\\xAD\\xA6\\xE6\\xB1\\x89\\xE5\\x86\\x85\\xE7\\x91\\x9F\\xE6\\x96\\xAF\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "03:8d:56:a1:21:53:e8:b5:c7:4c:69:bf:f6:5c:be:3f" and
            1605680260 <= pe.signatures[i].not_after
        )
}