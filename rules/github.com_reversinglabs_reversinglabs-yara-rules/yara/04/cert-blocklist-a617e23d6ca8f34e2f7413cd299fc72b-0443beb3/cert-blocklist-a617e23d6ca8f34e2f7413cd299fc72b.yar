import "pe"
rule cert_blocklist_a617e23d6ca8f34e2f7413cd299fc72b {
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
            pe.signatures[i].subject contains "EXPRESS BOOKS LTD" and (
                pe.signatures[i].serial == "00:a6:17:e2:3d:6c:a8:f3:4e:2f:74:13:cd:29:9f:c7:2b" or
                pe.signatures[i].serial == "a6:17:e2:3d:6c:a8:f3:4e:2f:74:13:cd:29:9f:c7:2b"
            ) and
            1636971821 <= pe.signatures[i].not_after
        )
}