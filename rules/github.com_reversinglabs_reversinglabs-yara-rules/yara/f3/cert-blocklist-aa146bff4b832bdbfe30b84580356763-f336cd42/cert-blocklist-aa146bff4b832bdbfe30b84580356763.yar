import "pe"
rule cert_blocklist_aa146bff4b832bdbfe30b84580356763 {
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
            pe.signatures[i].subject contains "Yancheng Peoples Information Technology Service Co., Ltd" and (
                pe.signatures[i].serial == "00:aa:14:6b:ff:4b:83:2b:db:fe:30:b8:45:80:35:67:63" or
                pe.signatures[i].serial == "aa:14:6b:ff:4b:83:2b:db:fe:30:b8:45:80:35:67:63"
            ) and
            1295481599 <= pe.signatures[i].not_after
        )
}