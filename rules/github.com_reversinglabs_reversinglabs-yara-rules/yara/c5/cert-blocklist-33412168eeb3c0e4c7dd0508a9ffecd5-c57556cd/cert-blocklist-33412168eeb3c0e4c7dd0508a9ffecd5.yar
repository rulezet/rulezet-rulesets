import "pe"
rule cert_blocklist_33412168eeb3c0e4c7dd0508a9ffecd5 {
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
            pe.signatures[i].serial == "33:41:21:68:ee:b3:c0:e4:c7:dd:05:08:a9:ff:ec:d5" and
            1467590400 <= pe.signatures[i].not_after
        )
}