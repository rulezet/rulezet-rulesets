import "pe"
rule cert_blocklist_d2caf7908aaebfa1a8f3e2136fece024 {
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
            pe.signatures[i].subject contains "FANATOR, OOO" and (
                pe.signatures[i].serial == "00:d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24" or
                pe.signatures[i].serial == "d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24"
            ) and
            1599041760 <= pe.signatures[i].not_after
        )
}