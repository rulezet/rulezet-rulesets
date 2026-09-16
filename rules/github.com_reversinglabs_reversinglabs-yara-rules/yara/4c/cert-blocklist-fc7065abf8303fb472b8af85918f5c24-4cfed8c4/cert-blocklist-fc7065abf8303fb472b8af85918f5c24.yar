import "pe"
rule cert_blocklist_fc7065abf8303fb472b8af85918f5c24 {
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
            pe.signatures[i].subject contains "DIG IN VISION SP Z O O" and (
                pe.signatures[i].serial == "00:fc:70:65:ab:f8:30:3f:b4:72:b8:af:85:91:8f:5c:24" or
                pe.signatures[i].serial == "fc:70:65:ab:f8:30:3f:b4:72:b8:af:85:91:8f:5c:24"
            ) and
            1604361600 <= pe.signatures[i].not_after
        )
}