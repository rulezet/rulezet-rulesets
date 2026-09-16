import "pe"
rule cert_blocklist_3ce65ea057b975d2c17eaf2c2297b1eb {
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
            pe.signatures[i].subject contains "TRANS LTD" and
            pe.signatures[i].serial == "3c:e6:5e:a0:57:b9:75:d2:c1:7e:af:2c:22:97:b1:eb" and
            1528243200 <= pe.signatures[i].not_after
        )
}