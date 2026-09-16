import "pe"
rule cert_blocklist_d8f515715aeffef0a0e4e37f16c254fa {
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
            pe.signatures[i].subject contains "HOLDING LA LTD" and (
                pe.signatures[i].serial == "00:d8:f5:15:71:5a:ef:fe:f0:a0:e4:e3:7f:16:c2:54:fa" or
                pe.signatures[i].serial == "d8:f5:15:71:5a:ef:fe:f0:a0:e4:e3:7f:16:c2:54:fa"
            ) and
            1619136000 <= pe.signatures[i].not_after
        )
}