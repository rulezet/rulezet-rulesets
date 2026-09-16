import "pe"
rule cert_blocklist_e38259cf24cc702ce441b683ad578911 {
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
            pe.signatures[i].subject contains "Akhirah Technologies Inc." and (
                pe.signatures[i].serial == "00:e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11" or
                pe.signatures[i].serial == "e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11"
            ) and
            1597276800 <= pe.signatures[i].not_after
        )
}