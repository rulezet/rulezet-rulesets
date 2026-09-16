import "pe"
rule cert_blocklist_6102468293ba7308d17efb43ad6bfb58 {
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
            pe.signatures[i].serial == "61:02:46:82:93:ba:73:08:d1:7e:fb:43:ad:6b:fb:58" and
            1470960000 <= pe.signatures[i].not_after
        )
}