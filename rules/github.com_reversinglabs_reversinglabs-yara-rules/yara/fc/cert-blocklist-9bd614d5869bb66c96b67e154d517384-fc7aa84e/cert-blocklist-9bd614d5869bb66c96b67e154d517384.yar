import "pe"
rule cert_blocklist_9bd614d5869bb66c96b67e154d517384 {
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
            pe.signatures[i].subject contains "\"CENTR MBP\"" and (
                pe.signatures[i].serial == "00:9b:d6:14:d5:86:9b:b6:6c:96:b6:7e:15:4d:51:73:84" or
                pe.signatures[i].serial == "9b:d6:14:d5:86:9b:b6:6c:96:b6:7e:15:4d:51:73:84"
            ) and
            1581618180 <= pe.signatures[i].not_after
        )
}