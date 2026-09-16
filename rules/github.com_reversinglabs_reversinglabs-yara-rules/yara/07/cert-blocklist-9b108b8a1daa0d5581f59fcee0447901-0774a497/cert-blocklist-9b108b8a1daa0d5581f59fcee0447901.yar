import "pe"
rule cert_blocklist_9b108b8a1daa0d5581f59fcee0447901 {
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
            pe.signatures[i].subject contains "CharacTell Ltd" and (
                pe.signatures[i].serial == "00:9b:10:8b:8a:1d:aa:0d:55:81:f5:9f:ce:e0:44:79:01" or
                pe.signatures[i].serial == "9b:10:8b:8a:1d:aa:0d:55:81:f5:9f:ce:e0:44:79:01"
            ) and
            1380671999 <= pe.signatures[i].not_after
        )
}