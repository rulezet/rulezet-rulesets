import "pe"
rule cert_blocklist_2d88c0af1fe2609961c171213c03bd23 {
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
            pe.signatures[i].subject contains "Zhuzhou Lizhong Precision Manufacturing Technology Co., Ltd." and
            pe.signatures[i].serial == "2d:88:c0:af:1f:e2:60:99:61:c1:71:21:3c:03:bd:23" and
            1683676800 <= pe.signatures[i].not_after
        )
}