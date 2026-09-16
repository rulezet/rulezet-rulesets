import "pe"
rule cert_blocklist_2433d9df7efbccb870ee5904d62a0101 {
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
            pe.signatures[i].subject contains "Conpavi AG" and
            pe.signatures[i].serial == "24:33:d9:df:7e:fb:cc:b8:70:ee:59:04:d6:2a:01:01" and
            1322438400 <= pe.signatures[i].not_after
        )
}