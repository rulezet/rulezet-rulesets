import "pe"
rule cert_blocklist_afc0ddb7bdc8207e8c3b7204018eecd3 {
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
            pe.signatures[i].subject contains "\\xE9\\x83\\xB4\\xE5\\xB7\\x9E\\xE8\\x9C\\x97\\xE7\\x89\\x9B\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (
                pe.signatures[i].serial == "00:af:c0:dd:b7:bd:c8:20:7e:8c:3b:72:04:01:8e:ec:d3" or
                pe.signatures[i].serial == "af:c0:dd:b7:bd:c8:20:7e:8c:3b:72:04:01:8e:ec:d3"
            ) and
            1629676800 <= pe.signatures[i].not_after
        )
}