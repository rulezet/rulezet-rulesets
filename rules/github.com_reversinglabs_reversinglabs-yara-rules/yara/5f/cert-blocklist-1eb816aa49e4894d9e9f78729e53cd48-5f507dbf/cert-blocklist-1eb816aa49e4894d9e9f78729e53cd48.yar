import "pe"
rule cert_blocklist_1eb816aa49e4894d9e9f78729e53cd48 {
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
            pe.signatures[i].subject contains "\\xE5\\x96\\x84\\xE5\\x90\\x9B \\xE9\\x9F\\xA6" and
            pe.signatures[i].serial == "1e:b8:16:aa:49:e4:89:4d:9e:9f:78:72:9e:53:cd:48" and
            1429056000 <= pe.signatures[i].not_after
        )
}