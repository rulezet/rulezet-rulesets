import "pe"
rule cert_blocklist_25bef28467e4750331d2f403458113b8 {
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
            pe.signatures[i].serial == "25:be:f2:84:67:e4:75:03:31:d2:f4:03:45:81:13:b8" and
            1474156800 <= pe.signatures[i].not_after
        )
}