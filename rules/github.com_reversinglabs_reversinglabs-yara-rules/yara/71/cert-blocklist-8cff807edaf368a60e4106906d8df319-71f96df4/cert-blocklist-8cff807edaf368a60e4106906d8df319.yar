import "pe"
rule cert_blocklist_8cff807edaf368a60e4106906d8df319 {
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
            pe.signatures[i].subject contains "KRAFT BOKS OOO" and (
                pe.signatures[i].serial == "00:8c:ff:80:7e:da:f3:68:a6:0e:41:06:90:6d:8d:f3:19" or
                pe.signatures[i].serial == "8c:ff:80:7e:da:f3:68:a6:0e:41:06:90:6d:8d:f3:19"
            ) and
            1598334455 <= pe.signatures[i].not_after
        )
}