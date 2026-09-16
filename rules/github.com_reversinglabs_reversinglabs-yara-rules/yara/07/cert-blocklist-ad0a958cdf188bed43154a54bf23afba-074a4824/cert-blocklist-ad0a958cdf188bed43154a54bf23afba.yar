import "pe"
rule cert_blocklist_ad0a958cdf188bed43154a54bf23afba {
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
            pe.signatures[i].subject contains "RHM Ltd" and (
                pe.signatures[i].serial == "00:ad:0a:95:8c:df:18:8b:ed:43:15:4a:54:bf:23:af:ba" or
                pe.signatures[i].serial == "ad:0a:95:8c:df:18:8b:ed:43:15:4a:54:bf:23:af:ba"
            ) and
            1612915200 <= pe.signatures[i].not_after
        )
}