import "pe"
rule cert_blocklist_a2a0ba281262acce7a00119e25564386 {
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
            pe.signatures[i].subject contains "Sopiteks LLC" and (
                pe.signatures[i].serial == "00:a2:a0:ba:28:12:62:ac:ce:7a:00:11:9e:25:56:43:86" or
                pe.signatures[i].serial == "a2:a0:ba:28:12:62:ac:ce:7a:00:11:9e:25:56:43:86"
            ) and
            1631908320 <= pe.signatures[i].not_after
        )
}