import "pe"
rule cert_blocklist_d627f1000d12485995514bfbdefc55d9 {
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
            pe.signatures[i].subject contains "THREE D CORPORATION PTY LTD" and (
                pe.signatures[i].serial == "00:d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9" or
                pe.signatures[i].serial == "d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9"
            ) and
            1597622400 <= pe.signatures[i].not_after
        )
}