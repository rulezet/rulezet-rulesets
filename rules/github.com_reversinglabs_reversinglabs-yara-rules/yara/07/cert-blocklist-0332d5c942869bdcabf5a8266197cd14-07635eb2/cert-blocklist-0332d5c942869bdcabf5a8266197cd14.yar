import "pe"
rule cert_blocklist_0332d5c942869bdcabf5a8266197cd14 {
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
            pe.signatures[i].subject contains "JAWRO SP Z O O" and
            pe.signatures[i].serial == "03:32:d5:c9:42:86:9b:dc:ab:f5:a8:26:61:97:cd:14" and
            1622160000 <= pe.signatures[i].not_after
        )
}