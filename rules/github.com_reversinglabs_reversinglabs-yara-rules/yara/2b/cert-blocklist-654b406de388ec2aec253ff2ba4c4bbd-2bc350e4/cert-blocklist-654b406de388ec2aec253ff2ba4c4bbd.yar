import "pe"
rule cert_blocklist_654b406de388ec2aec253ff2ba4c4bbd {
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
            pe.signatures[i].subject contains "Yijiajian (Amoy) Jiankan Tech Co.,LTD." and
            pe.signatures[i].serial == "65:4b:40:6d:e3:88:ec:2a:ec:25:3f:f2:ba:4c:4b:bd" and
            1398902400 <= pe.signatures[i].not_after
        )
}