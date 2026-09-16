import "pe"
rule cert_blocklist_f385e765acfb95605c9b35ca4c32f80e {
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
            pe.signatures[i].subject contains "CWI SOFTWARE LTDA" and (
                pe.signatures[i].serial == "00:f3:85:e7:65:ac:fb:95:60:5c:9b:35:ca:4c:32:f8:0e" or
                pe.signatures[i].serial == "f3:85:e7:65:ac:fb:95:60:5c:9b:35:ca:4c:32:f8:0e"
            ) and
            1382313599 <= pe.signatures[i].not_after
        )
}