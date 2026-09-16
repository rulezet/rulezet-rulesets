import "pe"
rule cert_blocklist_6aaa62208a3a78bfac1443007d031e61 {
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
            pe.signatures[i].subject contains "Solar LLC" and
            pe.signatures[i].serial == "6a:aa:62:20:8a:3a:78:bf:ac:14:43:00:7d:03:1e:61" and
            1608163200 <= pe.signatures[i].not_after
        )
}