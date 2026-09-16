import "pe"
rule cert_blocklist_3bc3bae4118d46f3fdd9beeeab749fee {
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
            pe.signatures[i].subject contains "\\xE6\\x9D\\x8E\\xE9\\x9B\\xAA\\xE6\\xA2\\x85" and
            pe.signatures[i].serial == "3b:c3:ba:e4:11:8d:46:f3:fd:d9:be:ee:ab:74:9f:ee" and
            1442275199 <= pe.signatures[i].not_after
        )
}