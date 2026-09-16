import "pe"
rule cert_blocklist_aa1d84779792b57f91fe7a4bde041942 {
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
            pe.signatures[i].subject contains "AXIUM NORTHWESTERN HYDRO INC." and (
                pe.signatures[i].serial == "00:aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42" or
                pe.signatures[i].serial == "aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42"
            ) and
            1639872000 <= pe.signatures[i].not_after
        )
}