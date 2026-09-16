import "pe"
rule cert_blocklist_21bfddb6a66435d1adce2ceb23ed7c9a {
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
            pe.signatures[i].subject contains "\\xE6\\x9D\\xA8\\xE6\\xB7\\x87\\xE6\\x99\\xBA" and
            pe.signatures[i].serial == "21:bf:dd:b6:a6:64:35:d1:ad:ce:2c:eb:23:ed:7c:9a" and
            1395297334 <= pe.signatures[i].not_after
        )
}