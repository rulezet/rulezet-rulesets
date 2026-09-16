import "pe"
rule cert_blocklist_dadf44e4046372313ee97b8e394c4079 {
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
            pe.signatures[i].subject contains "Digital Capital Management Ireland Limited" and (
                pe.signatures[i].serial == "00:da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79" or
                pe.signatures[i].serial == "da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79"
            ) and
            1600244736 <= pe.signatures[i].not_after
        )
}