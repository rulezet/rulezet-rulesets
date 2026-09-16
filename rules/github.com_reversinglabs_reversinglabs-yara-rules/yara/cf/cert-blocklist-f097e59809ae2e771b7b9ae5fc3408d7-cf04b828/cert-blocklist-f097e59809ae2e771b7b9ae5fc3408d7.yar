import "pe"
rule cert_blocklist_f097e59809ae2e771b7b9ae5fc3408d7 {
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
            pe.signatures[i].subject contains "ABEL RENOVATIONS, INC." and (
                pe.signatures[i].serial == "00:f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7" or
                pe.signatures[i].serial == "f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7"
            ) and
            1602542033 <= pe.signatures[i].not_after
        )
}