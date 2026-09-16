import "pe"
rule cert_blocklist_1b248c8508042d36bbd5d92d189c61d8 {
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
            pe.signatures[i].subject contains "Digital Robin Limited" and
            pe.signatures[i].serial == "1b:24:8c:85:08:04:2d:36:bb:d5:d9:2d:18:9c:61:d8" and
            1663171218 <= pe.signatures[i].not_after
        )
}