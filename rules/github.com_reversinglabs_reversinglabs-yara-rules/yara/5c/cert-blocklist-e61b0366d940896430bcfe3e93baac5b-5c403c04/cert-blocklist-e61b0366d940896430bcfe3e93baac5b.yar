import "pe"
rule cert_blocklist_e61b0366d940896430bcfe3e93baac5b {
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
            pe.signatures[i].subject contains "TRANS LTD" and (
                pe.signatures[i].serial == "00:e6:1b:03:66:d9:40:89:64:30:bc:fe:3e:93:ba:ac:5b" or
                pe.signatures[i].serial == "e6:1b:03:66:d9:40:89:64:30:bc:fe:3e:93:ba:ac:5b"
            ) and
            1528156800 <= pe.signatures[i].not_after
        )
}