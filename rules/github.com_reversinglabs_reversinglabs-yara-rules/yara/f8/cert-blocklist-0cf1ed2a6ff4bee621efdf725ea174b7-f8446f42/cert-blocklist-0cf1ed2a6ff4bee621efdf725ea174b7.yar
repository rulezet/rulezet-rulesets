import "pe"
rule cert_blocklist_0cf1ed2a6ff4bee621efdf725ea174b7 {
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
            pe.signatures[i].subject contains "LEVEL LIST SP Z O O" and
            pe.signatures[i].serial == "0c:f1:ed:2a:6f:f4:be:e6:21:ef:df:72:5e:a1:74:b7" and
            1603036100 <= pe.signatures[i].not_after
        )
}