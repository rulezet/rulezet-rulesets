import "pe"
rule cert_blocklist_cff2b275ba8a1dde83ac7ff858399a62 {
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
            pe.signatures[i].subject contains "XL-FORCE ApS" and (
                pe.signatures[i].serial == "00:cf:f2:b2:75:ba:8a:1d:de:83:ac:7f:f8:58:39:9a:62" or
                pe.signatures[i].serial == "cf:f2:b2:75:ba:8a:1d:de:83:ac:7f:f8:58:39:9a:62"
            ) and
            1636111842 <= pe.signatures[i].not_after
        )
}