import "pe"
rule cert_blocklist_effc6d19d6fc85872e4e5b3ccee6d301 {
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
            pe.signatures[i].subject contains "C\\xC3\\x93IR IP LIMITED" and (
                pe.signatures[i].serial == "00:ef:fc:6d:19:d6:fc:85:87:2e:4e:5b:3c:ce:e6:d3:01" or
                pe.signatures[i].serial == "ef:fc:6d:19:d6:fc:85:87:2e:4e:5b:3c:ce:e6:d3:01"
            ) and
            1572307200 <= pe.signatures[i].not_after
        )
}