import "pe"
rule cert_blocklist_0323cc4e38735b0e6efba76ea25c73b7 {
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
            pe.signatures[i].subject contains "Xingning Dexin Network Technology Co., Ltd." and
            pe.signatures[i].serial == "03:23:cc:4e:38:73:5b:0e:6e:fb:a7:6e:a2:5c:73:b7" and
            1512000000 <= pe.signatures[i].not_after
        )
}