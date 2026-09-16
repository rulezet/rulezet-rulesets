import "pe"
rule cert_blocklist_7def22ef4c645b1decfb36b6d3539dbf {
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
            pe.signatures[i].serial == "7d:ef:22:ef:4c:64:5b:1d:ec:fb:36:b6:d3:53:9d:bf" and
            1474416000 <= pe.signatures[i].not_after
        )
}