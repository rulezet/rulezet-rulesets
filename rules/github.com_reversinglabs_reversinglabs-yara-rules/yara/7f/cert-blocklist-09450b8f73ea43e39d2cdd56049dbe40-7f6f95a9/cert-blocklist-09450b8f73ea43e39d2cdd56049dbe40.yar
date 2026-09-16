import "pe"
rule cert_blocklist_09450b8f73ea43e39d2cdd56049dbe40 {
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
            pe.signatures[i].subject contains "\\xE4\\xB9\\x9D\\xE6\\xB1\\x9F\\xE5\\xAE\\x8F\\xE5\\x9B\\xBE\\xE6\\x97\\xA0\\xE5\\xBF\\xA7\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "09:45:0b:8f:73:ea:43:e3:9d:2c:dd:56:04:9d:be:40" and
            1561602110 <= pe.signatures[i].not_after
        )
}