import "pe"
rule cert_blocklist_0108cbaee60728f5bf06e45a56d6f170 {
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
            pe.signatures[i].subject contains "\\xE6\\xAD\\xA6\\xE6\\xB1\\x89\\xE4\\xB8\\x9C\\xE6\\xB9\\x96\\xE6\\x96\\xB0\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE5\\xBC\\x80\\xE5\\x8F\\x91\\xE5\\x8C\\xBA" and
            pe.signatures[i].serial == "01:08:cb:ae:e6:07:28:f5:bf:06:e4:5a:56:d6:f1:70" and
            1605680260 <= pe.signatures[i].not_after
        )
}