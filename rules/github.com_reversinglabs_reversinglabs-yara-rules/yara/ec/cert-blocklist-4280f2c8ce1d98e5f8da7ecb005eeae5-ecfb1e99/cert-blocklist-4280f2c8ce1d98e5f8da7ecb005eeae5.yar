import "pe"
rule cert_blocklist_4280f2c8ce1d98e5f8da7ecb005eeae5 {
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
            pe.signatures[i].serial == "42:80:f2:c8:ce:1d:98:e5:f8:da:7e:cb:00:5e:ea:e5" and
            1476316800 <= pe.signatures[i].not_after
        )
}