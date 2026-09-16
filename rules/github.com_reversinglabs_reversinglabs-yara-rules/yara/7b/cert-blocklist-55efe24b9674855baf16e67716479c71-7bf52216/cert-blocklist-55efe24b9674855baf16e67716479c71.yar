import "pe"
rule cert_blocklist_55efe24b9674855baf16e67716479c71 {
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
            pe.signatures[i].subject contains "S2BVISIO BELGIQUE SA" and
            pe.signatures[i].serial == "55:ef:e2:4b:96:74:85:5b:af:16:e6:77:16:47:9c:71" and
            1374451199 <= pe.signatures[i].not_after
        )
}