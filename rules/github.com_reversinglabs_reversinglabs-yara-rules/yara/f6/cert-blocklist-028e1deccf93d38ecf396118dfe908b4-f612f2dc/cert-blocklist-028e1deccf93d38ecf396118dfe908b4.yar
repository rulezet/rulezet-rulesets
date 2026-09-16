import "pe"
rule cert_blocklist_028e1deccf93d38ecf396118dfe908b4 {
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
            pe.signatures[i].subject contains "Fortuna Games Co., Ltd." and
            pe.signatures[i].serial == "02:8e:1d:ec:cf:93:d3:8e:cf:39:61:18:df:e9:08:b4" and
            1392163199 <= pe.signatures[i].not_after
        )
}