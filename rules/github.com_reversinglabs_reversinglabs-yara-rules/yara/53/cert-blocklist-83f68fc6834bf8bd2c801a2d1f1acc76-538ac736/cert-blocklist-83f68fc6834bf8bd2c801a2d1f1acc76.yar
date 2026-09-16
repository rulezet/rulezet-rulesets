import "pe"
rule cert_blocklist_83f68fc6834bf8bd2c801a2d1f1acc76 {
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
            pe.signatures[i].subject contains "Helpful Technologies, Inc" and (
                pe.signatures[i].serial == "00:83:f6:8f:c6:83:4b:f8:bd:2c:80:1a:2d:1f:1a:cc:76" or
                pe.signatures[i].serial == "83:f6:8f:c6:83:4b:f8:bd:2c:80:1a:2d:1f:1a:cc:76"
            ) and
            1407715199 <= pe.signatures[i].not_after
        )
}