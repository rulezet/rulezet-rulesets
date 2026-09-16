import "pe"
rule cert_blocklist_dc992ea8e6bb4926931df656d5eef8a0 {
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
            pe.signatures[i].subject contains "MEGAPOLISELIT, OOO" and (
                pe.signatures[i].serial == "00:dc:99:2e:a8:e6:bb:49:26:93:1d:f6:56:d5:ee:f8:a0" or
                pe.signatures[i].serial == "dc:99:2e:a8:e6:bb:49:26:93:1d:f6:56:d5:ee:f8:a0"
            ) and
            1497916800 <= pe.signatures[i].not_after
        )
}