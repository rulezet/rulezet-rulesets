import "pe"
rule cert_blocklist_04a0e92b0b9ebbb797df6ef52bd5ad05 {
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
            pe.signatures[i].serial == "04:a0:e9:2b:0b:9e:bb:b7:97:df:6e:f5:2b:d5:ad:05" and
            1479081600 <= pe.signatures[i].not_after
        )
}