import "pe"
rule cert_blocklist_9ae5b177ac3a7ce2aadf1c891b574924 {
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
            pe.signatures[i].subject contains "OOO Kolorit" and (
                pe.signatures[i].serial == "00:9a:e5:b1:77:ac:3a:7c:e2:aa:df:1c:89:1b:57:49:24" or
                pe.signatures[i].serial == "9a:e5:b1:77:ac:3a:7c:e2:aa:df:1c:89:1b:57:49:24"
            ) and
            1608076800 <= pe.signatures[i].not_after
        )
}