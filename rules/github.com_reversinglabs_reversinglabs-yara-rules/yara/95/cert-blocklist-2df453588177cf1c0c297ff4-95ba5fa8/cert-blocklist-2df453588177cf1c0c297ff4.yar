import "pe"
rule cert_blocklist_2df453588177cf1c0c297ff4 {
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
            pe.signatures[i].subject contains "Shenzhen Yunhuitianxia Technology Co.,Ltd." and
            pe.signatures[i].serial == "2d:f4:53:58:81:77:cf:1c:0c:29:7f:f4" and
            1479735173 <= pe.signatures[i].not_after
        )
}