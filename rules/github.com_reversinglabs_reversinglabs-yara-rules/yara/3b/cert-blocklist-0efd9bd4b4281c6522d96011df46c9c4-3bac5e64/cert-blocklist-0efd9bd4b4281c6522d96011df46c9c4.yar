import "pe"
rule cert_blocklist_0efd9bd4b4281c6522d96011df46c9c4 {
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
            pe.signatures[i].subject contains "\\xE9\\x9B\\xB7\\xE7\\xA5\\x9E\\xEF\\xBC\\x88\\xE6\\xAD\\xA6\\xE6\\xB1\\x89\\xEF\\xBC\\x89\\xE4\\xBF\\xA1\\xE6\\x81\\xAF\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "0e:fd:9b:d4:b4:28:1c:65:22:d9:60:11:df:46:c9:c4" and
            1586249095 <= pe.signatures[i].not_after
        )
}