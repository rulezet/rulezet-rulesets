import "pe"
rule cert_blocklist_4e2523e76ea455941e75fb8240474a75 {
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
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "4e:25:23:e7:6e:a4:55:94:1e:75:fb:82:40:47:4a:75" and
            1476403200 <= pe.signatures[i].not_after
        )
}