import "pe"
rule cert_blocklist_115cf1353a0e33e19099a4867a4c750a {
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
            pe.signatures[i].subject contains "212 NY Gifts, Inc." and (
                pe.signatures[i].serial == "00:11:5c:f1:35:3a:0e:33:e1:90:99:a4:86:7a:4c:75:0a" or
                pe.signatures[i].serial == "11:5c:f1:35:3a:0e:33:e1:90:99:a4:86:7a:4c:75:0a"
            ) and
            1605515909 <= pe.signatures[i].not_after
        )
}