import "pe"
rule cert_blocklist_86e5a9b9e89e5075c475006d0ca03832 {
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
            pe.signatures[i].subject contains "BlueMarble GmbH" and (
                pe.signatures[i].serial == "00:86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32" or
                pe.signatures[i].serial == "86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32"
            ) and
            1574791194 <= pe.signatures[i].not_after
        )
}