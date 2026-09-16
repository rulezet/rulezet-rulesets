import "pe"
rule cert_blocklist_6eb02ac2beb9611ed57eb12e {
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
            pe.signatures[i].subject contains "\\xE6\\x9D\\xA8\\xE5\\x87\\x8C\\xE4\\xBC\\xAF\\xE4\\xB9\\x90\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "6e:b0:2a:c2:be:b9:61:1e:d5:7e:b1:2e" and
            1585023767 <= pe.signatures[i].not_after
        )
}