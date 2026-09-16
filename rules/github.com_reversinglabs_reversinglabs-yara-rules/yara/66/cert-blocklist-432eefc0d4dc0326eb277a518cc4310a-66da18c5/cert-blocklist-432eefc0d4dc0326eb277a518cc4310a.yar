import "pe"
rule cert_blocklist_432eefc0d4dc0326eb277a518cc4310a {
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
            pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and
            pe.signatures[i].serial == "43:2e:ef:c0:d4:dc:03:26:eb:27:7a:51:8c:c4:31:0a" and
            1466121600 <= pe.signatures[i].not_after
        )
}